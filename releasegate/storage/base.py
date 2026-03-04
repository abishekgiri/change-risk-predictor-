from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Sequence

import os


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = str(raw).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def require_tenant_id() -> bool:
    """
    Strict tenant-boundary mode:
    - default: required
    - opt-out: set RELEASEGATE_REQUIRE_TENANT_ID=false (dev/test only)
    """
    return _env_bool("RELEASEGATE_REQUIRE_TENANT_ID", True)


def resolve_tenant_id(tenant_id: Optional[str] = None, *, allow_none: bool = False) -> Optional[str]:
    """
    Resolve tenant identity to a stable non-empty value.
    """
    raw = str(tenant_id or os.getenv("RELEASEGATE_TENANT_ID") or "").strip()
    if raw:
        return raw
    if allow_none:
        return None
    if not require_tenant_id():
        return "default"
    raise ValueError("tenant_id is required. Provide --tenant or set RELEASEGATE_TENANT_ID.")


class StorageBackend(ABC):
    """
    Backend-agnostic storage interface for audit and governance records.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @contextmanager
    @abstractmethod
    def connect(self) -> Iterator[Any]:
        raise NotImplementedError

    @abstractmethod
    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
        raise NotImplementedError

    @abstractmethod
    def fetchone(self, query: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def fetchall(self, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @contextmanager
    @abstractmethod
    def transaction(self) -> Iterator["StorageBackend"]:
        """
        Execute multiple statements atomically.
        Inside this context, execute()/fetch*() must use the same connection and
        must not auto-commit per statement.
        """
        raise NotImplementedError
