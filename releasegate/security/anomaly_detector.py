from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from releasegate.security.security_state_service import (
    SECURITY_STATE_LOCKED,
    SECURITY_STATE_NORMAL,
    SECURITY_STATE_THROTTLED,
    get_tenant_security_state,
    set_tenant_security_state,
)
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db

_DEFAULT_RULES: Dict[str, Dict[str, int]] = {
    "failed_override_attempt": {"throttle": 100, "lock": 200, "window_minutes": 10},
    "replay_nonce_abuse": {"throttle": 20, "lock": 40, "window_minutes": 10},
    "policy_tamper_attempt": {"throttle": 5, "lock": 10, "window_minutes": 10},
    "signature_verification_failed": {"throttle": 100, "lock": 200, "window_minutes": 10},
    "quota_bypass_attempt": {"throttle": 20, "lock": 40, "window_minutes": 10},
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _signal_token(signal_type: str) -> str:
    return str(signal_type or "unknown").strip().lower().replace("-", "_")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = int(str(raw).strip())
        return parsed if parsed > 0 else default
    except Exception:
        return default


def _rule(signal_type: str) -> Dict[str, int]:
    token = _signal_token(signal_type)
    base = dict(_DEFAULT_RULES.get(token) or {"throttle": 100, "lock": 200, "window_minutes": 10})
    upper = token.upper()
    base["window_minutes"] = _env_int(
        f"RELEASEGATE_ANOMALY_{upper}_WINDOW_MINUTES",
        _env_int("RELEASEGATE_ANOMALY_WINDOW_MINUTES", base["window_minutes"]),
    )
    base["throttle"] = _env_int(f"RELEASEGATE_ANOMALY_{upper}_THROTTLE", base["throttle"])
    base["lock"] = _env_int(f"RELEASEGATE_ANOMALY_{upper}_LOCK", base["lock"])
    if base["lock"] < base["throttle"]:
        base["lock"] = base["throttle"]
    return base


def _ensure_anomaly_table() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_security_anomaly_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            signal_type TEXT NOT NULL,
            operation TEXT,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_security_anomaly_events_signal_created
        ON tenant_security_anomaly_events(tenant_id, signal_type, created_at DESC)
        """
    )


def record_anomaly_event(
    *,
    tenant_id: str,
    signal_type: str,
    operation: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    actor: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    _ensure_anomaly_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    signal = _signal_token(signal_type)
    rule = _rule(signal)
    now = _utc_now()
    now_iso = now.isoformat()
    cutoff = (now - timedelta(minutes=max(1, int(rule["window_minutes"]))))

    event_id = uuid.uuid4().hex
    storage.execute(
        """
        INSERT INTO tenant_security_anomaly_events (
            tenant_id, event_id, signal_type, operation, details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            event_id,
            signal,
            str(operation or "").strip() or None,
            json.dumps(details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            now_iso,
        ),
    )

    row = storage.fetchone(
        """
        SELECT COUNT(1) AS cnt
        FROM tenant_security_anomaly_events
        WHERE tenant_id = ? AND signal_type = ? AND created_at >= ?
        """,
        (effective_tenant, signal, cutoff.isoformat()),
    ) or {}
    count = int(row.get("cnt") or 0)

    state = get_tenant_security_state(tenant_id=effective_tenant)
    current_state = str(state.get("security_state") or SECURITY_STATE_NORMAL)
    transition = None

    if count >= int(rule["lock"]) and current_state != SECURITY_STATE_LOCKED:
        transition = set_tenant_security_state(
            tenant_id=effective_tenant,
            to_state=SECURITY_STATE_LOCKED,
            reason=f"Anomaly threshold exceeded: {signal}",
            source="anomaly_detector",
            actor=actor,
            metadata={
                "signal_type": signal,
                "count_in_window": count,
                "window_minutes": int(rule["window_minutes"]),
                "threshold": int(rule["lock"]),
            },
        )
    elif (
        count >= int(rule["throttle"])
        and current_state == SECURITY_STATE_NORMAL
    ):
        transition = set_tenant_security_state(
            tenant_id=effective_tenant,
            to_state=SECURITY_STATE_THROTTLED,
            reason=f"Anomaly threshold exceeded: {signal}",
            source="anomaly_detector",
            actor=actor,
            metadata={
                "signal_type": signal,
                "count_in_window": count,
                "window_minutes": int(rule["window_minutes"]),
                "threshold": int(rule["throttle"]),
            },
        )

    return {
        "tenant_id": effective_tenant,
        "event_id": event_id,
        "signal_type": signal,
        "operation": str(operation or "").strip() or None,
        "count_in_window": count,
        "window_minutes": int(rule["window_minutes"]),
        "thresholds": {
            "throttle": int(rule["throttle"]),
            "lock": int(rule["lock"]),
        },
        "state_transition": transition,
    }
