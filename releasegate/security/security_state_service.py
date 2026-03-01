from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db

SECURITY_STATE_NORMAL = "normal"
SECURITY_STATE_THROTTLED = "throttled"
SECURITY_STATE_LOCKED = "locked"
_SECURITY_STATES = {SECURITY_STATE_NORMAL, SECURITY_STATE_THROTTLED, SECURITY_STATE_LOCKED}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_state(value: Optional[str]) -> str:
    state = str(value or SECURITY_STATE_NORMAL).strip().lower()
    if state not in _SECURITY_STATES:
        return SECURITY_STATE_NORMAL
    return state


def _ensure_security_tables() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_governance_settings (
            tenant_id TEXT PRIMARY KEY,
            max_decisions_per_month INTEGER,
            max_anchors_per_day INTEGER,
            max_overrides_per_month INTEGER,
            quota_enforcement_mode TEXT NOT NULL DEFAULT 'HARD',
            security_state TEXT NOT NULL DEFAULT 'normal',
            security_reason TEXT,
            security_since TEXT,
            updated_at TEXT NOT NULL,
            updated_by TEXT
        )
        """
    )
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_security_state_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            from_state TEXT NOT NULL,
            to_state TEXT NOT NULL,
            reason TEXT,
            source TEXT,
            actor TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_security_state_events_created
        ON tenant_security_state_events(tenant_id, created_at DESC)
        """
    )


def _ensure_governance_row(*, tenant_id: str, now_iso: str) -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO tenant_governance_settings (
            tenant_id,
            max_decisions_per_month,
            max_anchors_per_day,
            max_overrides_per_month,
            quota_enforcement_mode,
            security_state,
            security_reason,
            security_since,
            updated_at,
            updated_by
        ) VALUES (?, NULL, NULL, NULL, 'HARD', 'normal', NULL, NULL, ?, 'system')
        ON CONFLICT(tenant_id) DO NOTHING
        """,
        (tenant_id, now_iso),
    )


def get_tenant_security_state(*, tenant_id: str) -> Dict[str, Any]:
    init_db()
    _ensure_security_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT security_state, security_reason, security_since, updated_at, updated_by
        FROM tenant_governance_settings
        WHERE tenant_id = ?
        LIMIT 1
        """,
        (effective_tenant,),
    ) or {}
    return {
        "tenant_id": effective_tenant,
        "security_state": _normalize_state(row.get("security_state")),
        "security_reason": row.get("security_reason"),
        "security_since": row.get("security_since"),
        "updated_at": row.get("updated_at"),
        "updated_by": row.get("updated_by"),
    }


def set_tenant_security_state(
    *,
    tenant_id: str,
    to_state: str,
    reason: Optional[str],
    source: str,
    actor: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    _ensure_security_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    new_state = _normalize_state(to_state)
    now_iso = _utc_now_iso()
    normalized_reason = str(reason or "").strip() or None
    normalized_source = str(source or "").strip() or "system"
    normalized_actor = str(actor or "").strip() or None

    with storage.transaction():
        _ensure_governance_row(tenant_id=effective_tenant, now_iso=now_iso)
        current = storage.fetchone(
            """
            SELECT security_state, security_reason, security_since
            FROM tenant_governance_settings
            WHERE tenant_id = ?
            LIMIT 1
            """,
            (effective_tenant,),
        ) or {}
        from_state = _normalize_state(current.get("security_state"))
        if from_state == new_state and str(current.get("security_reason") or "") == str(normalized_reason or ""):
            return {
                "tenant_id": effective_tenant,
                "from_state": from_state,
                "to_state": new_state,
                "reason": current.get("security_reason"),
                "security_since": current.get("security_since"),
                "changed": False,
            }

        security_since = now_iso if new_state != from_state else str(current.get("security_since") or now_iso)
        storage.execute(
            """
            UPDATE tenant_governance_settings
            SET security_state = ?,
                security_reason = ?,
                security_since = ?,
                updated_at = ?,
                updated_by = ?
            WHERE tenant_id = ?
            """,
            (
                new_state,
                normalized_reason,
                security_since,
                now_iso,
                normalized_actor or normalized_source,
                effective_tenant,
            ),
        )
        event_id = uuid.uuid4().hex
        storage.execute(
            """
            INSERT INTO tenant_security_state_events (
                tenant_id, event_id, from_state, to_state, reason, source, actor, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                event_id,
                from_state,
                new_state,
                normalized_reason,
                normalized_source,
                normalized_actor,
                json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                now_iso,
            ),
        )

    return {
        "tenant_id": effective_tenant,
        "event_id": event_id,
        "from_state": from_state,
        "to_state": new_state,
        "reason": normalized_reason,
        "security_since": security_since,
        "source": normalized_source,
        "actor": normalized_actor,
        "changed": True,
    }


def list_tenant_security_state_events(*, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    init_db()
    _ensure_security_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    effective_limit = max(1, min(int(limit), 500))
    rows = storage.fetchall(
        """
        SELECT tenant_id, event_id, from_state, to_state, reason, source, actor, metadata_json, created_at
        FROM tenant_security_state_events
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (effective_tenant, effective_limit),
    )
    for row in rows:
        raw = row.get("metadata_json")
        if isinstance(raw, str):
            try:
                row["metadata"] = json.loads(raw)
            except Exception:
                row["metadata"] = {}
        elif isinstance(raw, dict):
            row["metadata"] = dict(raw)
        else:
            row["metadata"] = {}
    return rows


def enforce_tenant_operation_allowed(*, tenant_id: str, operation: Optional[str] = None) -> None:
    state = get_tenant_security_state(tenant_id=tenant_id)
    if state["security_state"] != SECURITY_STATE_LOCKED:
        return
    raise HTTPException(
        status_code=423,
        detail={
            "error": "TENANT_LOCKED",
            "tenant_id": state["tenant_id"],
            "reason": state.get("security_reason") or "Tenant is locked due to suspicious activity.",
            "security_since": state.get("security_since"),
            "operation": str(operation or "").strip() or None,
        },
    )
