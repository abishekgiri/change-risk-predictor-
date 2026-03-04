from __future__ import annotations

import os
from typing import Any, Dict, Optional


def _to_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def resolve_strict_fail_closed(
    *,
    policy_overrides: Optional[Dict[str, Any]],
    fallback: bool = True,
) -> bool:
    env_default = _to_bool(
        os.getenv("RELEASEGATE_STRICT_FAIL_CLOSED"),
        default=fallback,
    )
    overrides = policy_overrides or {}
    return _to_bool(overrides.get("strict_fail_closed"), default=env_default)


def apply_strict_fail_closed(
    *,
    strict_enabled: bool,
    policy_loaded: bool = True,
    risk_present: Optional[bool] = None,
    signals_stale: bool = False,
    provider_error: Optional[str] = None,
    provider_timeout: bool = False,
) -> Optional[Dict[str, str]]:
    if not strict_enabled:
        return None
    if not policy_loaded:
        return {
            "reason_code": "POLICY_MISSING",
            "reason": "Policy bundle is missing in strict mode.",
        }
    if risk_present is False:
        return {
            "reason_code": "RISK_MISSING",
            "reason": "Risk metadata is missing in strict mode.",
        }
    if signals_stale:
        return {
            "reason_code": "SIGNAL_STALE",
            "reason": "Required signals are stale in strict mode.",
        }
    if provider_timeout:
        return {
            "reason_code": "PROVIDER_TIMEOUT",
            "reason": "Dependency timeout in strict mode.",
        }
    if provider_error:
        return {
            "reason_code": "PROVIDER_ERROR",
            "reason": f"Dependency error in strict mode ({provider_error}).",
        }
    return None
