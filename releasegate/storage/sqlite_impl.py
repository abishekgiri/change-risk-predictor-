from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

import sqlite3
import threading

from releasegate.config import DB_PATH
from releasegate.storage.base import StorageBackend


class SQLiteStorageBackend(StorageBackend):
    def __init__(self):
        self._local = threading.local()

    @property
    def name(self) -> str:
        return "sqlite"

    def _active_tx(self) -> Optional[Dict[str, Any]]:
        return getattr(self._local, "tx_state", None)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        active = self._active_tx()
        if active is not None:
            yield active["conn"]
            return
        db_file = Path(DB_PATH)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
        active = self._active_tx()
        if active is not None:
            cur = active["conn"].cursor()
            cur.execute(query, tuple(params))
            return cur.rowcount
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            conn.commit()
            return cur.rowcount

    def fetchone(self, query: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        active = self._active_tx()
        if active is not None:
            cur = active["conn"].cursor()
            cur.execute(query, tuple(params))
            row = cur.fetchone()
            return dict(row) if row else None
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            row = cur.fetchone()
            return dict(row) if row else None

    def fetchall(self, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        active = self._active_tx()
        if active is not None:
            cur = active["conn"].cursor()
            cur.execute(query, tuple(params))
            return [dict(r) for r in cur.fetchall()]
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            return [dict(r) for r in cur.fetchall()]

    @contextmanager
    def transaction(self) -> Iterator["SQLiteStorageBackend"]:
        active = self._active_tx()
        if active is not None:
            active["depth"] += 1
            try:
                yield self
            finally:
                active["depth"] -= 1
            return

        db_file = Path(DB_PATH)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        self._local.tx_state = {"conn": conn, "depth": 1}
        try:
            yield self
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._local.tx_state = None
            conn.close()
