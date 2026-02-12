from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def store_policy_bundle(
    *,
    tenant_id: Optional[str],
    policy_bundle_hash: str,
    policy_snapshot: List[Dict[str, Any]],
    is_active: bool = True,
) -> None:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    bundle_json = json.dumps(policy_snapshot or [], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    storage.execute(
        """
        INSERT INTO policy_bundles (tenant_id, policy_bundle_hash, bundle_json, is_active, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, policy_bundle_hash) DO UPDATE SET
            bundle_json = excluded.bundle_json,
            is_active = CASE
                WHEN excluded.is_active = 1 THEN 1
                ELSE policy_bundles.is_active
            END
        """,
        (
            effective_tenant,
            policy_bundle_hash,
            bundle_json,
            1 if is_active else 0,
            datetime.now(timezone.utc).isoformat(),
        ),
    )


def get_policy_bundle(*, tenant_id: Optional[str], policy_bundle_hash: str) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, policy_bundle_hash, bundle_json, is_active, created_at
        FROM policy_bundles
        WHERE tenant_id = ? AND policy_bundle_hash = ?
        LIMIT 1
        """,
        (effective_tenant, policy_bundle_hash),
    )
    if not row:
        return None
    bundle_json = row.get("bundle_json")
    try:
        snapshot = json.loads(bundle_json) if isinstance(bundle_json, str) else (bundle_json or [])
    except Exception:
        snapshot = []
    return {
        "tenant_id": row.get("tenant_id"),
        "policy_bundle_hash": row.get("policy_bundle_hash"),
        "policy_snapshot": snapshot,
        "is_active": bool(row.get("is_active")),
        "created_at": row.get("created_at"),
    }


def get_latest_active_policy_bundle(*, tenant_id: Optional[str]) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, policy_bundle_hash, bundle_json, is_active, created_at
        FROM policy_bundles
        WHERE tenant_id = ? AND is_active = 1
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (effective_tenant,),
    )
    if not row:
        return None
    bundle_json = row.get("bundle_json")
    try:
        snapshot = json.loads(bundle_json) if isinstance(bundle_json, str) else (bundle_json or [])
    except Exception:
        snapshot = []
    return {
        "tenant_id": row.get("tenant_id"),
        "policy_bundle_hash": row.get("policy_bundle_hash"),
        "policy_snapshot": snapshot,
        "is_active": bool(row.get("is_active")),
        "created_at": row.get("created_at"),
    }

