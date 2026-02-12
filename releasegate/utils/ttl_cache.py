from __future__ import annotations

import hashlib
import os
import time
from collections import OrderedDict
from threading import Lock
from typing import Any, Iterable, Optional, Tuple


class TTLCache:
    """
    Tiny in-process TTL + LRU cache.
    Values are cached per key until expiry; oldest entries are evicted past max size.
    """

    def __init__(self, *, max_entries: int = 256, default_ttl_seconds: float = 300.0):
        self._max_entries = max(1, int(max_entries))
        self._default_ttl_seconds = max(0.0, float(default_ttl_seconds))
        self._entries: "OrderedDict[Any, Tuple[float, Any]]" = OrderedDict()
        self._lock = Lock()

    def get(self, key: Any) -> Tuple[bool, Any]:
        now = time.monotonic()
        with self._lock:
            row = self._entries.get(key)
            if row is None:
                return False, None
            expires_at, value = row
            if expires_at < now:
                self._entries.pop(key, None)
                return False, None
            self._entries.move_to_end(key)
            return True, value

    def set(self, key: Any, value: Any, *, ttl_seconds: Optional[float] = None) -> None:
        ttl = self._default_ttl_seconds if ttl_seconds is None else max(0.0, float(ttl_seconds))
        expires_at = time.monotonic() + ttl
        with self._lock:
            self._entries[key] = (expires_at, value)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def delete_prefix(self, prefix: Tuple[Any, ...]) -> int:
        removed = 0
        plen = len(prefix)
        with self._lock:
            for key in list(self._entries.keys()):
                if isinstance(key, tuple) and key[:plen] == prefix:
                    self._entries.pop(key, None)
                    removed += 1
        return removed


def file_fingerprint(path: str) -> str:
    """
    Fast fingerprint for config files using metadata.
    """
    normalized = os.path.abspath(path)
    try:
        stat = os.stat(normalized)
        payload = f"{normalized}:{stat.st_size}:{int(stat.st_mtime_ns)}"
    except OSError:
        payload = f"{normalized}:missing"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def yaml_tree_fingerprint(root_dir: str) -> str:
    """
    Fingerprint a YAML policy directory from file metadata only.
    """
    normalized = os.path.abspath(root_dir)
    parts = []
    if not os.path.isdir(normalized):
        parts.append(f"{normalized}:missing")
    else:
        for dirpath, _, filenames in os.walk(normalized):
            for name in sorted(filenames):
                if not (name.endswith(".yaml") or name.endswith(".yml")):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    stat = os.stat(full)
                    parts.append(f"{os.path.relpath(full, normalized)}:{stat.st_size}:{int(stat.st_mtime_ns)}")
                except OSError:
                    parts.append(f"{os.path.relpath(full, normalized)}:missing")
    payload = "|".join(parts) if parts else f"{normalized}:empty"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def stable_tuple(values: Iterable[Any]) -> Tuple[str, ...]:
    return tuple(sorted(str(v).strip() for v in values if str(v).strip()))

