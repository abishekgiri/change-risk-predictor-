from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Sequence

import os

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

    @property
    def name(self) -> str:
        return "postgres"

    def _adapt_sql(self, query: str) -> str:
        # Existing codebase uses sqlite-style '?' placeholders.
        return query.replace("?", "%s")

    @contextmanager
    def connect(self) -> Iterator[Any]:
        conn = psycopg2.connect(self._dsn)
        try:
            yield conn
        finally:
            conn.close()

    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
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
        with self.connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                q = self._adapt_sql(query)
                if params:
                    cur.execute(q, tuple(params))
                else:
                    cur.execute(q)
                rows = cur.fetchall()
                return [dict(r) for r in rows]
