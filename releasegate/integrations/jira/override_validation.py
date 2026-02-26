from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional, Sequence


ACTION_LOCK = "LOCK"
ACTION_UNLOCK = "UNLOCK"
ACTION_OVERRIDE = "OVERRIDE"
_DEFAULT_MAX_TTL_SECONDS = 7 * 24 * 60 * 60
_DEFAULT_MIN_JUSTIFICATION_LEN = 20


@dataclass(frozen=True)
class OverrideValidationResult:
    allowed: bool
    reason_code: str
    message: str
    ttl_seconds: Optional[int] = None
    expires_at: Optional[str] = None
    justification: Optional[str] = None


def _int_env(name: str, default: int) -> int:
    raw = str(os.getenv(name, str(default)) or str(default)).strip()
    try:
        return int(raw)
    except Exception:
        return int(default)


def _normalize_roles(roles: Optional[Sequence[str]]) -> set[str]:
    normalized = set()
    for role in roles or []:
        value = str(role or "").strip().lower()
        if value:
            normalized.add(value)
    return normalized


def _parse_ttl_seconds(raw: object) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        return int(float(text))
    except Exception:
        return None


def _is_low_quality_justification(value: str) -> bool:
    compact = "".join(ch for ch in value.lower() if ch.isalnum())
    if len(set(compact)) < 4:
        return True
    if len(compact) >= 8 and compact == compact[0] * len(compact):
        return True
    tokens = [part for part in value.strip().split() if part]
    return len(tokens) < 3


def validate_override_request(
    *,
    action: str,
    ttl_seconds: object,
    justification: object,
    actor_roles: Optional[Iterable[str]],
    idempotency_key: Optional[str],
    now: Optional[datetime] = None,
) -> OverrideValidationResult:
    normalized_action = str(action or "").strip().upper() or ACTION_OVERRIDE
    roles = _normalize_roles(list(actor_roles or []))
    require_admin = normalized_action in {ACTION_OVERRIDE, ACTION_UNLOCK}
    require_ttl = normalized_action in {ACTION_OVERRIDE, ACTION_UNLOCK}
    require_justification = normalized_action in {ACTION_OVERRIDE, ACTION_UNLOCK, ACTION_LOCK}
    max_ttl_seconds = max(1, _int_env("RELEASEGATE_OVERRIDE_MAX_TTL_SECONDS", _DEFAULT_MAX_TTL_SECONDS))
    min_justification_len = max(1, _int_env("RELEASEGATE_OVERRIDE_MIN_JUSTIFICATION_LEN", _DEFAULT_MIN_JUSTIFICATION_LEN))

    if not str(idempotency_key or "").strip():
        return OverrideValidationResult(
            allowed=False,
            reason_code="OVERRIDE_IDEMPOTENCY_REQUIRED",
            message="Idempotency-Key is required for override operations.",
        )

    if require_admin and "admin" not in roles:
        return OverrideValidationResult(
            allowed=False,
            reason_code="OVERRIDE_ADMIN_REQUIRED",
            message="Admin role is required for override operations.",
        )

    parsed_ttl = _parse_ttl_seconds(ttl_seconds)
    if require_ttl and parsed_ttl is None:
        return OverrideValidationResult(
            allowed=False,
            reason_code="OVERRIDE_TTL_REQUIRED",
            message="Override TTL is required and must be a positive integer.",
        )

    if parsed_ttl is not None and parsed_ttl <= 0:
        return OverrideValidationResult(
            allowed=False,
            reason_code="OVERRIDE_TTL_INVALID",
            message="Override TTL must be greater than zero seconds.",
        )

    if parsed_ttl is not None and parsed_ttl > max_ttl_seconds:
        return OverrideValidationResult(
            allowed=False,
            reason_code="OVERRIDE_TTL_TOO_LARGE",
            message=f"Override TTL exceeds maximum of {max_ttl_seconds} seconds.",
        )

    cleaned_justification = str(justification or "").strip()
    if require_justification and len(cleaned_justification) < min_justification_len:
        return OverrideValidationResult(
            allowed=False,
            reason_code="OVERRIDE_JUSTIFICATION_REQUIRED",
            message=f"Override justification must be at least {min_justification_len} characters.",
        )

    if cleaned_justification and _is_low_quality_justification(cleaned_justification):
        return OverrideValidationResult(
            allowed=False,
            reason_code="OVERRIDE_JUSTIFICATION_LOW_QUALITY",
            message="Override justification is too short or low quality for audit requirements.",
        )

    effective_now = now or datetime.now(timezone.utc)
    expires_at = None
    if parsed_ttl is not None:
        expires_at = (effective_now + timedelta(seconds=parsed_ttl)).isoformat()

    return OverrideValidationResult(
        allowed=True,
        reason_code="OVERRIDE_VALID",
        message="Override request validated.",
        ttl_seconds=parsed_ttl,
        expires_at=expires_at,
        justification=cleaned_justification or None,
    )
