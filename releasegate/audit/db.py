from __future__ import annotations

import sqlite3

from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db


def get_connection() -> sqlite3.Connection:
    """
    Backward-compatible SQLite connection helper for audit modules.
    """
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

