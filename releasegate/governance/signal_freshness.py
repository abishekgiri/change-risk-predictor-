from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.utils.canonical import sha256_json


def _to_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raw = str(value).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _to_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _parse_datetime(value: Any) -> Optional[datetime]:
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
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _risk_signal_material(risk_meta: Dict[str, Any]) -> Dict[str, Any]:
    metrics = risk_meta.get("metrics") if isinstance(risk_meta.get("metrics"), dict) else {}
    return {
        "releasegate_risk": risk_meta.get("releasegate_risk") or risk_meta.get("risk_level"),
        "risk_score": risk_meta.get("risk_score") or risk_meta.get("severity"),
        "source": risk_meta.get("source"),
        "repo": risk_meta.get("repo"),
        "pr_number": risk_meta.get("pr_number"),
        "computed_at": risk_meta.get("computed_at"),
        "metrics": metrics,
    }


def compute_risk_signal_hash(risk_meta: Dict[str, Any]) -> str:
    return f"sha256:{sha256_json(_risk_signal_material(risk_meta))}"


def ensure_risk_signal_hash(risk_meta: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(risk_meta or {})
    existing = str(enriched.get("signal_hash") or "").strip()
    if existing:
        return enriched
    enriched["signal_hash"] = compute_risk_signal_hash(enriched)
    return enriched


def resolve_signal_freshness_policy(
    *,
    policy_overrides: Optional[Dict[str, Any]],
    strict_enabled: bool,
) -> Dict[str, Any]:
    overrides = policy_overrides if isinstance(policy_overrides, dict) else {}
    max_age = _to_int(
        overrides.get("max_age_seconds", os.getenv("RELEASEGATE_SIGNAL_MAX_AGE_SECONDS", "3600")),
        default=3600,
    )
    require_computed_at = _to_bool(
        overrides.get("require_computed_at", os.getenv("RELEASEGATE_REQUIRE_SIGNAL_COMPUTED_AT", "true")),
        default=True,
    )
    require_signal_hash = _to_bool(
        overrides.get("require_signal_hash", os.getenv("RELEASEGATE_REQUIRE_SIGNAL_HASH", "false")),
        default=False,
    )
    fail_on_stale = _to_bool(
        overrides.get("fail_on_stale", os.getenv("RELEASEGATE_FAIL_ON_STALE", "true")),
        default=True,
    )
    return {
        "max_age_seconds": max(0, max_age),
        "require_computed_at": require_computed_at,
        "require_signal_hash": require_signal_hash,
        "fail_on_stale": fail_on_stale,
        "strict_enabled": bool(strict_enabled),
    }


def evaluate_risk_signal_freshness(
    *,
    risk_meta: Dict[str, Any],
    policy: Dict[str, Any],
    evaluation_time: Optional[datetime] = None,
) -> Dict[str, Any]:
    evaluated_at = evaluation_time or datetime.now(timezone.utc)
    if evaluated_at.tzinfo is None:
        evaluated_at = evaluated_at.replace(tzinfo=timezone.utc)
    evaluated_at = evaluated_at.astimezone(timezone.utc)

    require_computed_at = bool(policy.get("require_computed_at", True))
    require_signal_hash = bool(policy.get("require_signal_hash", False))
    fail_on_stale = bool(policy.get("fail_on_stale", True))
    strict_enabled = bool(policy.get("strict_enabled", False))
    max_age_seconds = int(policy.get("max_age_seconds", 3600) or 0)

    computed_at_raw = risk_meta.get("computed_at")
    computed_at = _parse_datetime(computed_at_raw)
    if require_computed_at and computed_at is None:
        return {
            "stale": True,
            "should_block": bool(fail_on_stale and strict_enabled),
            "reason_code": "SIGNAL_STALE_COMPUTED_AT_MISSING",
            "reason": "risk signal is missing computed_at",
            "details": {
                "computed_at": computed_at_raw,
                "max_age_seconds": max_age_seconds,
            },
        }

    signal_hash_raw = str(risk_meta.get("signal_hash") or "").strip()
    expected_hash = compute_risk_signal_hash(risk_meta)
    if require_signal_hash and not signal_hash_raw:
        return {
            "stale": True,
            "should_block": bool(fail_on_stale and strict_enabled),
            "reason_code": "SIGNAL_HASH_MISSING",
            "reason": "risk signal is missing signal_hash",
            "details": {
                "expected_signal_hash": expected_hash,
            },
        }
    if require_signal_hash and signal_hash_raw and signal_hash_raw != expected_hash:
        return {
            "stale": True,
            "should_block": bool(fail_on_stale and strict_enabled),
            "reason_code": "SIGNAL_HASH_MISMATCH",
            "reason": "risk signal hash does not match payload",
            "details": {
                "provided_signal_hash": signal_hash_raw,
                "expected_signal_hash": expected_hash,
            },
        }

    age_seconds = None
    if computed_at is not None:
        age_seconds = max(0, int((evaluated_at - computed_at).total_seconds()))
        if max_age_seconds > 0 and age_seconds > max_age_seconds:
            return {
                "stale": True,
                "should_block": bool(fail_on_stale and strict_enabled),
                "reason_code": "SIGNAL_STALE",
                "reason": "risk signal is older than max_age_seconds",
                "details": {
                    "computed_at": computed_at.isoformat(),
                    "evaluation_time": evaluated_at.isoformat(),
                    "age_seconds": age_seconds,
                    "max_age_seconds": max_age_seconds,
                },
            }

    return {
        "stale": False,
        "should_block": False,
        "reason_code": None,
        "reason": "ok",
        "details": {
            "computed_at": computed_at.isoformat() if computed_at else None,
            "evaluation_time": evaluated_at.isoformat(),
            "age_seconds": age_seconds,
            "max_age_seconds": max_age_seconds,
        },
    }
