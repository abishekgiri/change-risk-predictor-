"""Thin DB connection shim for commercial / fabric ad-hoc queries.

Existing `StorageBackend` is the right abstraction for committed app code,
but a few modules (commercial/*, future ad-hoc reports) need raw `%s`-style
queries portable across SQLite (dev) and Postgres (prod).

This module resolves the configured backend and returns a connection-like
object with two helpful additions:

  conn.dialect            → "sqlite" | "postgres"
  conn.cursor()           → DB-API cursor; on SQLite, %s placeholders are
                            translated to ? automatically so callers can
                            write Postgres-style SQL uniformly.

For dialect-specific SQL fragments (time windows, JSON ops) use the helpers
below — they return literals that are safe to inline (they do not accept
user input; `days` must be an int).
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

from releasegate.config import DB_PATH


def _resolve_backend_name() -> str:
    return (os.getenv("RELEASEGATE_STORAGE_BACKEND") or "sqlite").strip().lower()


class _SqliteCursorShim:
    """Wraps a sqlite3.Cursor and translates %s placeholders to ?."""

    __slots__ = ("_cur",)

    def __init__(self, cur: sqlite3.Cursor):
        self._cur = cur

    @staticmethod
    def _translate(sql: str) -> str:
        # Naive but sufficient: our queries do not contain '%s' inside string
        # literals. If that ever changes, revisit.
        return sql.replace("%s", "?")

    def execute(self, sql: str, params: Iterable[Any] = ()):
        return self._cur.execute(self._translate(sql), tuple(params))

    def executemany(self, sql: str, seq):
        return self._cur.executemany(self._translate(sql), seq)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    @property
    def description(self):
        return self._cur.description

    @property
    def rowcount(self):
        return self._cur.rowcount

    def close(self):
        return self._cur.close()


class _SqliteConnShim:
    """Wrap a sqlite3.Connection so its cursors translate %s → ?."""

    __slots__ = ("_conn", "dialect")

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self.dialect = "sqlite"

    def cursor(self):
        return _SqliteCursorShim(self._conn.cursor())

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()


class _PgConnShim:
    """Tag a psycopg2 connection with .dialect='postgres' without altering behaviour."""

    __slots__ = ("_conn", "dialect")

    def __init__(self, conn):
        self._conn = conn
        self.dialect = "postgres"

    def cursor(self):
        return self._conn.cursor()

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()


def get_db_connection():
    """Return a dialect-tagged DB connection.

    Callers may use %s placeholders regardless of backend; SQLite path
    translates them.  For Postgres-specific SQL (NOW(), INTERVAL, JSONB)
    see the `window_predicate`, `now_sql`, and `json_array_len_sql` helpers.
    """
    backend = _resolve_backend_name()
    if backend == "postgres":
        try:
            import psycopg2  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("psycopg2 is required for Postgres backend") from exc
        dsn = os.getenv("RELEASEGATE_POSTGRES_DSN") or os.getenv("DATABASE_URL")
        if not dsn:
            raise ValueError("Postgres DSN missing. Set RELEASEGATE_POSTGRES_DSN or DATABASE_URL.")
        return _PgConnShim(psycopg2.connect(dsn))

    # SQLite (default)
    db_file = Path(DB_PATH)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = None  # tuples — commercial code indexes by position
    return _SqliteConnShim(conn)


# ── Dialect helpers ──────────────────────────────────────────────────────────


def window_predicate(dialect: str, column: str, days: int) -> str:
    """Return a WHERE-clause fragment filtering `column` to the last `days` days.

    `days` is coerced to int to ensure it is safe for inline use (no SQL
    injection vector; no user string ever reaches the query text).
    """
    days_int = max(0, int(days))
    if dialect == "postgres":
        return f"{column} >= NOW() - INTERVAL '{days_int} days'"
    # SQLite: ISO-8601 string comparison using datetime('now', '-Nd')
    return f"{column} >= datetime('now', '-{days_int} days')"


def now_sql(dialect: str) -> str:
    return "NOW()" if dialect == "postgres" else "datetime('now')"


def json_array_len_sql(dialect: str, column: str) -> str:
    """SQL expression that evaluates to len(json_array_in_column), 0 if NULL/empty."""
    if dialect == "postgres":
        # Postgres: handle text columns that may hold JSON
        return (
            f"COALESCE(CASE WHEN {column} IS NULL OR {column} = '' "
            f"THEN 0 ELSE jsonb_array_length({column}::jsonb) END, 0)"
        )
    # SQLite: json_array_length returns 0 for '[]', raises on invalid JSON.
    # Guard NULL/empty to 0.
    return (
        f"COALESCE(CASE WHEN {column} IS NULL OR {column} = '' "
        f"THEN 0 ELSE json_array_length({column}) END, 0)"
    )


def epoch_hours_diff_sql(dialect: str, later: str, earlier: str) -> str:
    """Hours between two timestamp columns, as a float."""
    if dialect == "postgres":
        return f"EXTRACT(EPOCH FROM ({later} - {earlier})) / 3600.0"
    # SQLite: julianday returns days; multiply by 24 for hours.
    return f"(julianday({later}) - julianday({earlier})) * 24.0"


def column_exists(conn, table: str, column: str) -> bool:
    """Return True if `table.column` exists on this connection's backend."""
    dialect = getattr(conn, "dialect", "sqlite")
    cur = conn.cursor()
    try:
        if dialect == "postgres":
            cur.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = %s AND column_name = %s",
                (table, column),
            )
            return cur.fetchone() is not None
        # SQLite: pragma_table_info
        cur.execute(f"PRAGMA table_info({table})")
        return any(row[1] == column for row in cur.fetchall())
    except Exception:
        return False
