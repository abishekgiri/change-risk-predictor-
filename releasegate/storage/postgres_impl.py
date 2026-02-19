from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Sequence

import os
import threading

from releasegate.storage.base import StorageBackend

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:  # pragma: no cover
    psycopg2 = None
    RealDictCursor = None


class PostgresStorageBackend(StorageBackend):
    def __init__(self, dsn: Optional[str] = None):
        self._dsn = (
            dsn
            or os.getenv("RELEASEGATE_POSTGRES_DSN")
            or os.getenv("DATABASE_URL")
        )
        if not self._dsn:
            raise ValueError("Postgres DSN missing. Set RELEASEGATE_POSTGRES_DSN or DATABASE_URL.")
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is required for PostgresStorageBackend")
        self._local = threading.local()

    @property
    def name(self) -> str:
        return "postgres"

    def _adapt_sql(self, query: str) -> str:
        # Existing codebase uses sqlite-style '?' placeholders.
        return query.replace("?", "%s")

    def _active_tx(self) -> Optional[Dict[str, Any]]:
        return getattr(self._local, "tx_state", None)

    @contextmanager
    def connect(self) -> Iterator[Any]:
        active = self._active_tx()
        if active is not None:
            yield active["conn"]
            return
        conn = psycopg2.connect(self._dsn)
        try:
            yield conn
        finally:
            conn.close()

    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
        active = self._active_tx()
        if active is not None:
            with active["conn"].cursor() as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                return cur.rowcount
        with self.connect() as conn:
            with conn.cursor() as cur:
                q = self._adapt_sql(query)
                # psycopg2 treats '%' as interpolation markers when a params tuple is
                # provided (even an empty one). Some DDL (e.g., plpgsql RAISE strings)
                # legitimately contains '%' characters, so avoid passing params when
                # there are none.
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                conn.commit()
                return cur.rowcount

    def fetchone(self, query: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        active = self._active_tx()
        if active is not None:
            with active["conn"].cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                row = cur.fetchone()
                return dict(row) if row else None
        with self.connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                row = cur.fetchone()
                return dict(row) if row else None

    def fetchall(self, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        active = self._active_tx()
        if active is not None:
            with active["conn"].cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        with self.connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                rows = cur.fetchall()
                return [dict(r) for r in rows]

    @contextmanager
    def transaction(self) -> Iterator["PostgresStorageBackend"]:
        active = self._active_tx()
        if active is not None:
            active["depth"] += 1
            try:
                yield self
            finally:
                active["depth"] -= 1
            return

        conn = psycopg2.connect(self._dsn)
        state = {"conn": conn, "depth": 1}
        self._local.tx_state = state
        try:
            yield self
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._local.tx_state = None
            conn.close()
