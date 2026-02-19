from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return default
    if isinstance(value, (dict, list)):
        return value
    return default


def record_replay_event(
    *,
    tenant_id: Optional[str],
    decision_id: str,
    match: bool,
    diff: List[Dict[str, Any]],
    old_output_hash: Optional[str],
    new_output_hash: Optional[str],
    old_policy_hash: Optional[str],
    new_policy_hash: Optional[str],
    old_input_hash: Optional[str],
    new_input_hash: Optional[str],
    ran_engine_version: str,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    replay_id = str(uuid.uuid4())
    created_at = _utc_now()
    storage.execute(
        """
        INSERT INTO audit_decision_replays (
            tenant_id, replay_id, decision_id, match, diff_json, old_output_hash, new_output_hash,
            old_policy_hash, new_policy_hash, old_input_hash, new_input_hash, ran_engine_version, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            replay_id,
            str(decision_id),
            1 if match else 0,
            canonical_json(diff or []),
            str(old_output_hash or "") or None,
            str(new_output_hash or "") or None,
            str(old_policy_hash or "") or None,
            str(new_policy_hash or "") or None,
            str(old_input_hash or "") or None,
            str(new_input_hash or "") or None,
            str(ran_engine_version or "unknown"),
            created_at,
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "replay_id": replay_id,
        "decision_id": str(decision_id),
        "match": bool(match),
        "diff": diff or [],
        "old_output_hash": old_output_hash,
        "new_output_hash": new_output_hash,
        "old_policy_hash": old_policy_hash,
        "new_policy_hash": new_policy_hash,
        "old_input_hash": old_input_hash,
        "new_input_hash": new_input_hash,
        "ran_engine_version": str(ran_engine_version or "unknown"),
        "created_at": created_at,
    }


def list_replay_events(
    *,
    tenant_id: Optional[str],
    decision_id: str,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    rows = storage.fetchall(
        """
        SELECT tenant_id, replay_id, decision_id, match, diff_json, old_output_hash, new_output_hash,
               old_policy_hash, new_policy_hash, old_input_hash, new_input_hash, ran_engine_version, created_at
        FROM audit_decision_replays
        WHERE tenant_id = ? AND decision_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (effective_tenant, str(decision_id), max(1, int(limit))),
    )
    items: List[Dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "tenant_id": row.get("tenant_id"),
                "replay_id": row.get("replay_id"),
                "decision_id": row.get("decision_id"),
                "match": bool(int(row.get("match") or 0)),
                "diff": _loads(row.get("diff_json"), []),
                "old_output_hash": row.get("old_output_hash"),
                "new_output_hash": row.get("new_output_hash"),
                "old_policy_hash": row.get("old_policy_hash"),
                "new_policy_hash": row.get("new_policy_hash"),
                "old_input_hash": row.get("old_input_hash"),
                "new_input_hash": row.get("new_input_hash"),
                "ran_engine_version": row.get("ran_engine_version"),
                "created_at": row.get("created_at"),
            }
        )
    return items

