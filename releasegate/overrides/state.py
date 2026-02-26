from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional


class OverrideState(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except Exception:
            return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def resolve_override_state(
    override: Mapping[str, Any],
    now_utc: Optional[datetime] = None,
    *,
    require_expires_at: bool = True,
) -> OverrideState:
    effective_now = _parse_iso_datetime(now_utc) if now_utc is not None else datetime.now(timezone.utc)
    if effective_now is None:
        effective_now = datetime.now(timezone.utc)

    revoked_at = (
        override.get("revoked_at")
        or override.get("deleted_at")
        or override.get("invalidated_at")
    )
    if revoked_at:
        return OverrideState.REVOKED

    expires_at = _parse_iso_datetime(override.get("expires_at"))
    if expires_at is None:
        return OverrideState.EXPIRED if require_expires_at else OverrideState.ACTIVE
    if effective_now > expires_at:
        return OverrideState.EXPIRED
    return OverrideState.ACTIVE
