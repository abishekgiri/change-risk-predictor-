from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

import sqlite3

from releasegate.config import DB_PATH
from releasegate.storage.base import StorageBackend


class SQLiteStorageBackend(StorageBackend):
    @property
    def name(self) -> str:
        return "sqlite"

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db_file = Path(DB_PATH)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            conn.commit()
            return cur.rowcount

    def fetchone(self, query: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            row = cur.fetchone()
            return dict(row) if row else None

    def fetchall(self, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            return [dict(r) for r in cur.fetchall()]

