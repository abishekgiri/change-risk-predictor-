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


# Substrings that indicate the storage backend is simply not available
# in this environment (no writable SQLite path, no reachable Postgres) —
# as opposed to a genuine SQL/logic error.  Used by the customer-side
# CLI path: a CI runner with no DB configured must still sign and emit a
# DSSE attestation; persistence is a server/dashboard concern and is
# skipped silently when the backend cannot be reached.  Real errors
# (constraint violations, bad SQL, etc.) do NOT match and are re-raised.
_STORAGE_UNAVAILABLE_SIGNALS = (
    "unable to open database file",       # sqlite: no writable data/ dir
    "could not connect",                  # postgres: server unreachable
    "connection refused",                 # postgres: server unreachable
    "could not translate host name",      # postgres: bad/absent host
    "name or service not known",          # postgres: DNS failure
    "no such host",                        # postgres: DNS failure
    "could not open database",            # generic open failure
)


def is_storage_unavailable_error(exc: BaseException) -> bool:
    """True when an exception means 'no DB backend here', not 'bad query'.

    The customer-install signing path (Marketplace Action in a CI runner)
    has no database.  Callers use this to skip persistence gracefully
    while still re-raising genuine storage errors.
    """
    message = str(exc).lower()
    return any(signal in message for signal in _STORAGE_UNAVAILABLE_SIGNALS)
