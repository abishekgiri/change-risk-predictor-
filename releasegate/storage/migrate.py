from __future__ import annotations

from typing import Dict, List

from releasegate.storage import get_storage_backend
from releasegate.storage.schema import init_db


def migrate() -> str:
    """
    Apply all pending forward-only migrations.
    """
    return init_db()


def migration_status() -> Dict[str, List[dict]]:
    """
    Return applied migration history.
    """
    init_db()
    storage = get_storage_backend()
    rows = storage.fetchall(
        """
        SELECT migration_id, description, applied_at
        FROM schema_migrations
        ORDER BY migration_id ASC
        """
    )
    return {"applied": rows}
