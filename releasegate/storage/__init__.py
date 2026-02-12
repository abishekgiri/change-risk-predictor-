from __future__ import annotations

import os
from functools import lru_cache

from releasegate.storage.base import StorageBackend
from releasegate.storage.postgres_impl import PostgresStorageBackend
from releasegate.storage.sqlite_impl import SQLiteStorageBackend


@lru_cache(maxsize=1)
def get_storage_backend() -> StorageBackend:
    backend = (os.getenv("RELEASEGATE_STORAGE_BACKEND") or "sqlite").strip().lower()
    if backend == "postgres":
        return PostgresStorageBackend()
    return SQLiteStorageBackend()


def get_artifact_store():
    from releasegate.storage.artifact_store import ArtifactStore

    return ArtifactStore()
