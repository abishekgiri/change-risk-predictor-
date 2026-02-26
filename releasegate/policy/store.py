from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_registry_event(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    event_type: str,
    actor_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    event_id = str(uuid.uuid4())
    created_at = _utc_now()
    storage.execute(
        """
        INSERT INTO policy_registry_events (
            tenant_id, event_id, policy_id, event_type, actor_id, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            event_id,
            str(policy_id),
            str(event_type),
            str(actor_id or "") or None,
            json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            created_at,
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "event_id": event_id,
        "policy_id": str(policy_id),
        "event_type": str(event_type),
        "actor_id": str(actor_id or "") or None,
        "metadata": metadata or {},
        "created_at": created_at,
    }


def list_registry_events(
    *,
    tenant_id: Optional[str],
    policy_id: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    query = [
        """
        SELECT tenant_id, event_id, policy_id, event_type, actor_id, metadata_json, created_at
        FROM policy_registry_events
        WHERE tenant_id = ?
        """
    ]
    params: List[Any] = [effective_tenant]
    if policy_id:
        query.append("AND policy_id = ?")
        params.append(str(policy_id))
    query.append("ORDER BY created_at DESC")
    query.append("LIMIT ?")
    params.append(max(1, min(int(limit), 500)))
    rows = storage.fetchall("\n".join(query), params)
    events: List[Dict[str, Any]] = []
    for row in rows:
        raw_metadata = row.get("metadata_json")
        metadata: Dict[str, Any] = {}
        if isinstance(raw_metadata, dict):
            metadata = raw_metadata
        elif isinstance(raw_metadata, str):
            try:
                parsed = json.loads(raw_metadata)
                if isinstance(parsed, dict):
                    metadata = parsed
            except Exception:
                metadata = {}
        events.append(
            {
                "tenant_id": row.get("tenant_id"),
                "event_id": row.get("event_id"),
                "policy_id": row.get("policy_id"),
                "event_type": row.get("event_type"),
                "actor_id": row.get("actor_id"),
                "metadata": metadata,
                "created_at": row.get("created_at"),
            }
        )
    return events

