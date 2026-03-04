from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.policy.snapshots import (
    get_resolved_policy_snapshot,
    get_resolved_policy_snapshot_by_hash,
)
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


POLICY_RELEASE_STATES = {"DRAFT", "SCHEDULED", "ACTIVE", "SUPERSEDED", "ROLLED_BACK"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_state(state: str) -> str:
    normalized = str(state or "").strip().upper() or "DRAFT"
    if normalized not in POLICY_RELEASE_STATES:
        raise ValueError(f"invalid policy release state: {state}")
    return normalized


def _normalize_env(target_env: str) -> str:
    value = str(target_env or "").strip().lower()
    if not value:
        raise ValueError("target_env is required")
    return value


def _parse_iso_timestamp(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"invalid ISO timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _ensure_snapshot(
    *,
    tenant_id: str,
    snapshot_id: Optional[str],
    policy_hash: Optional[str],
) -> Dict[str, Any]:
    snapshot: Optional[Dict[str, Any]] = None
    if snapshot_id:
        snapshot = get_resolved_policy_snapshot(tenant_id=tenant_id, snapshot_id=snapshot_id)
    elif policy_hash:
        snapshot = get_resolved_policy_snapshot_by_hash(tenant_id=tenant_id, policy_hash=policy_hash)
    if not snapshot:
        raise ValueError("resolved policy snapshot not found")
    return snapshot


def _append_release_event(
    *,
    tenant_id: str,
    release_id: str,
    event_type: str,
    actor_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    event_id = str(uuid.uuid4())
    created_at = _utc_now()
    payload = metadata or {}
    storage.execute(
        """
        INSERT INTO policy_release_events (
            tenant_id, event_id, release_id, event_type, actor_id, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            event_id,
            release_id,
            str(event_type),
            str(actor_id or "") or None,
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            created_at,
        ),
    )
    return {
        "tenant_id": tenant_id,
        "event_id": event_id,
        "release_id": release_id,
        "event_type": event_type,
        "actor_id": actor_id,
        "metadata": payload,
        "created_at": created_at,
    }


def get_policy_release(
    *,
    tenant_id: Optional[str],
    release_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    return storage.fetchone(
        """
        SELECT tenant_id, release_id, policy_id, snapshot_id, target_env, state,
               effective_at, activated_at, created_by, change_ticket, created_at
        FROM policy_releases
        WHERE tenant_id = ? AND release_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(release_id)),
    )


def create_policy_release(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    target_env: str,
    created_by: Optional[str],
    snapshot_id: Optional[str] = None,
    policy_hash: Optional[str] = None,
    state: str = "DRAFT",
    effective_at: Optional[str] = None,
    change_ticket: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_state = _normalize_state(state)
    normalized_env = _normalize_env(target_env)
    snapshot = _ensure_snapshot(
        tenant_id=effective_tenant,
        snapshot_id=snapshot_id,
        policy_hash=policy_hash,
    )
    resolved_snapshot_id = str(snapshot.get("snapshot_id") or "")
    if not resolved_snapshot_id:
        raise ValueError("snapshot_id missing from resolved policy snapshot")

    effective_at_iso = _parse_iso_timestamp(effective_at)
    if normalized_state == "SCHEDULED" and not effective_at_iso:
        raise ValueError("effective_at is required for scheduled policy releases")

    release_id = str(uuid.uuid4())
    created_at = _utc_now()
    storage.execute(
        """
        INSERT INTO policy_releases (
            tenant_id, release_id, policy_id, snapshot_id, target_env, state,
            effective_at, activated_at, created_by, change_ticket, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            release_id,
            str(policy_id),
            resolved_snapshot_id,
            normalized_env,
            normalized_state,
            effective_at_iso,
            _utc_now() if normalized_state == "ACTIVE" else None,
            str(created_by or "") or None,
            str(change_ticket or "") or None,
            created_at,
        ),
    )
    _append_release_event(
        tenant_id=effective_tenant,
        release_id=release_id,
        event_type="RELEASE_CREATED",
        actor_id=created_by,
        metadata={
            "state": normalized_state,
            "policy_id": str(policy_id),
            "target_env": normalized_env,
            "snapshot_id": resolved_snapshot_id,
            "effective_at": effective_at_iso,
        },
    )
    if normalized_state == "ACTIVE":
        activate_policy_release(
            tenant_id=effective_tenant,
            release_id=release_id,
            actor_id=created_by,
        )
    return get_policy_release(tenant_id=effective_tenant, release_id=release_id) or {
        "tenant_id": effective_tenant,
        "release_id": release_id,
        "policy_id": str(policy_id),
        "snapshot_id": resolved_snapshot_id,
        "target_env": normalized_env,
        "state": normalized_state,
        "effective_at": effective_at_iso,
        "activated_at": None,
        "created_by": created_by,
        "change_ticket": change_ticket,
        "created_at": created_at,
    }


def activate_policy_release(
    *,
    tenant_id: Optional[str],
    release_id: str,
    actor_id: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    release = get_policy_release(tenant_id=effective_tenant, release_id=release_id)
    if not release:
        raise ValueError("policy release not found")
    now_iso = _utc_now()
    storage.execute(
        """
        UPDATE policy_releases
        SET state = ?, activated_at = ?
        WHERE tenant_id = ? AND policy_id = ? AND target_env = ? AND release_id != ? AND state = ?
        """,
        ("SUPERSEDED", now_iso, effective_tenant, release["policy_id"], release["target_env"], release_id, "ACTIVE"),
    )
    storage.execute(
        """
        UPDATE policy_releases
        SET state = ?, activated_at = COALESCE(activated_at, ?)
        WHERE tenant_id = ? AND release_id = ?
        """,
        ("ACTIVE", now_iso, effective_tenant, release_id),
    )
    storage.execute(
        """
        INSERT INTO active_policy_pointers (tenant_id, policy_id, target_env, active_release_id, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, policy_id, target_env) DO UPDATE SET
            active_release_id = excluded.active_release_id,
            updated_at = excluded.updated_at
        """,
        (
            effective_tenant,
            release["policy_id"],
            release["target_env"],
            release_id,
            now_iso,
        ),
    )
    _append_release_event(
        tenant_id=effective_tenant,
        release_id=release_id,
        event_type="RELEASE_ACTIVATED",
        actor_id=actor_id,
        metadata={
            "policy_id": release["policy_id"],
            "target_env": release["target_env"],
        },
    )
    return get_policy_release(tenant_id=effective_tenant, release_id=release_id) or release


def get_active_policy_release(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    target_env: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_env = _normalize_env(target_env)
    row = storage.fetchone(
        """
        SELECT p.tenant_id, p.policy_id, p.target_env, p.active_release_id, p.updated_at,
               r.snapshot_id, r.state, r.effective_at, r.activated_at, r.created_by, r.change_ticket, r.created_at
        FROM active_policy_pointers p
        JOIN policy_releases r
          ON p.tenant_id = r.tenant_id AND p.active_release_id = r.release_id
        WHERE p.tenant_id = ? AND p.policy_id = ? AND p.target_env = ?
        LIMIT 1
        """,
        (effective_tenant, str(policy_id), normalized_env),
    )
    if not row:
        return None
    snapshot = get_resolved_policy_snapshot(
        tenant_id=effective_tenant,
        snapshot_id=str(row.get("snapshot_id") or ""),
    )
    return {
        "tenant_id": row.get("tenant_id"),
        "policy_id": row.get("policy_id"),
        "target_env": row.get("target_env"),
        "active_release_id": row.get("active_release_id"),
        "updated_at": row.get("updated_at"),
        "release": {
            "release_id": row.get("active_release_id"),
            "snapshot_id": row.get("snapshot_id"),
            "state": row.get("state"),
            "effective_at": row.get("effective_at"),
            "activated_at": row.get("activated_at"),
            "created_by": row.get("created_by"),
            "change_ticket": row.get("change_ticket"),
            "created_at": row.get("created_at"),
        },
        "snapshot": snapshot,
    }


def promote_policy_release(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    source_env: str,
    target_env: str,
    created_by: Optional[str],
    state: str = "DRAFT",
    effective_at: Optional[str] = None,
    change_ticket: Optional[str] = None,
) -> Dict[str, Any]:
    active_source = get_active_policy_release(
        tenant_id=tenant_id,
        policy_id=policy_id,
        target_env=source_env,
    )
    if not active_source:
        raise ValueError("source environment has no active policy release")
    snapshot_id = str((active_source.get("release") or {}).get("snapshot_id") or "")
    if not snapshot_id:
        raise ValueError("source environment active release is missing snapshot_id")
    created = create_policy_release(
        tenant_id=tenant_id,
        policy_id=policy_id,
        target_env=target_env,
        created_by=created_by,
        snapshot_id=snapshot_id,
        state=state,
        effective_at=effective_at,
        change_ticket=change_ticket,
    )
    _append_release_event(
        tenant_id=resolve_tenant_id(tenant_id),
        release_id=created["release_id"],
        event_type="RELEASE_PROMOTED",
        actor_id=created_by,
        metadata={
            "policy_id": policy_id,
            "source_env": _normalize_env(source_env),
            "target_env": _normalize_env(target_env),
            "source_release_id": (active_source.get("release") or {}).get("release_id"),
        },
    )
    return created


def rollback_policy_release(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    target_env: str,
    to_release_id: str,
    actor_id: Optional[str],
    change_ticket: Optional[str] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    historical = get_policy_release(tenant_id=effective_tenant, release_id=to_release_id)
    if not historical:
        raise ValueError("rollback source release not found")
    if str(historical.get("policy_id") or "") != str(policy_id):
        raise ValueError("rollback source release policy_id mismatch")
    if _normalize_env(str(historical.get("target_env") or "")) != _normalize_env(target_env):
        raise ValueError("rollback source release target_env mismatch")
    rollback_release = create_policy_release(
        tenant_id=effective_tenant,
        policy_id=policy_id,
        target_env=target_env,
        created_by=actor_id,
        snapshot_id=str(historical.get("snapshot_id") or ""),
        state="ACTIVE",
        change_ticket=change_ticket,
    )
    _append_release_event(
        tenant_id=effective_tenant,
        release_id=rollback_release["release_id"],
        event_type="RELEASE_ROLLED_BACK",
        actor_id=actor_id,
        metadata={
            "policy_id": policy_id,
            "target_env": _normalize_env(target_env),
            "rollback_to_release_id": str(to_release_id),
        },
    )
    return rollback_release


def run_policy_release_scheduler(
    *,
    tenant_id: Optional[str] = None,
    actor_id: str = "scheduler",
    now: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id, allow_none=True)
    now_iso = _parse_iso_timestamp(now) or _utc_now()
    query = """
        SELECT tenant_id, release_id
        FROM policy_releases
        WHERE state = ? AND effective_at IS NOT NULL AND effective_at <= ?
    """
    params: List[Any] = ["SCHEDULED", now_iso]
    if effective_tenant:
        query += " AND tenant_id = ?"
        params.append(effective_tenant)
    query += " ORDER BY effective_at ASC, created_at ASC"
    due = storage.fetchall(query, params)

    activated: List[Dict[str, Any]] = []
    for row in due:
        activated.append(
            activate_policy_release(
                tenant_id=row.get("tenant_id"),
                release_id=str(row.get("release_id") or ""),
                actor_id=actor_id,
            )
        )
    return {
        "scheduled_evaluated_at": now_iso,
        "activated_count": len(activated),
        "activated_releases": activated,
    }
