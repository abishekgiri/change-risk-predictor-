from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.policy.releases import (
    activate_policy_release,
    get_active_policy_release,
    get_policy_release,
)
from releasegate.policy.snapshots import get_resolved_policy_snapshot
from releasegate.rollout.rollout_models import (
    ROLLOUT_MODE_CANARY,
    ROLLOUT_MODE_FULL,
    ROLLOUT_STATE_COMPLETED,
    ROLLOUT_STATE_ROLLED_BACK,
    ROLLOUT_STATE_RUNNING,
    normalize_canary_percent,
    normalize_rollout_mode,
)
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_json_field(raw: Any, fallback: Any) -> Any:
    if raw is None:
        return fallback
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, type(fallback)):
                return parsed
        except json.JSONDecodeError:
            return fallback
    return fallback


def _hash_bucket(*, tenant_id: str, rollout_id: str, rollout_key: str) -> int:
    material = f"{tenant_id}:{rollout_id}:{rollout_key}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    return int(digest[:16], 16) % 100


def _append_rollout_event(
    *,
    tenant_id: str,
    rollout_id: str,
    event_type: str,
    actor_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    created_at = _utc_now()
    event_id = str(uuid.uuid4())
    payload = metadata or {}
    storage.execute(
        """
        INSERT INTO policy_rollout_events (
            tenant_id, event_id, rollout_id, event_type, actor_id, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            event_id,
            rollout_id,
            str(event_type),
            str(actor_id or "") or None,
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            created_at,
        ),
    )
    return {
        "tenant_id": tenant_id,
        "event_id": event_id,
        "rollout_id": rollout_id,
        "event_type": event_type,
        "actor_id": str(actor_id or "") or None,
        "metadata": payload,
        "created_at": created_at,
    }


def _serialize_rollout_row(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "tenant_id": row.get("tenant_id"),
        "rollout_id": row.get("rollout_id"),
        "policy_id": row.get("policy_id"),
        "target_env": row.get("target_env"),
        "from_release_id": row.get("from_release_id"),
        "to_release_id": row.get("to_release_id"),
        "mode": row.get("mode"),
        "canary_percent": int(row.get("canary_percent") or 0),
        "state": row.get("state"),
        "rollback_to_release_id": row.get("rollback_to_release_id"),
        "created_by": row.get("created_by"),
        "started_at": row.get("started_at"),
        "completed_at": row.get("completed_at"),
        "updated_at": row.get("updated_at"),
        "metadata": _parse_json_field(row.get("metadata_json"), {}),
    }


def get_policy_rollout(*, tenant_id: Optional[str], rollout_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, rollout_id, policy_id, target_env,
               from_release_id, to_release_id, mode, canary_percent,
               state, rollback_to_release_id, created_by,
               started_at, completed_at, updated_at, metadata_json
        FROM policy_rollouts
        WHERE tenant_id = ? AND rollout_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(rollout_id)),
    )
    return _serialize_rollout_row(row)


def list_policy_rollouts(
    *,
    tenant_id: Optional[str],
    policy_id: Optional[str] = None,
    target_env: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    query = [
        """
        SELECT tenant_id, rollout_id, policy_id, target_env,
               from_release_id, to_release_id, mode, canary_percent,
               state, rollback_to_release_id, created_by,
               started_at, completed_at, updated_at, metadata_json
        FROM policy_rollouts
        WHERE tenant_id = ?
        """
    ]
    params: List[Any] = [effective_tenant]
    if policy_id:
        query.append("AND policy_id = ?")
        params.append(str(policy_id))
    if target_env:
        query.append("AND target_env = ?")
        params.append(str(target_env).strip().lower())
    if state:
        query.append("AND state = ?")
        params.append(str(state).strip().upper())
    query.append("ORDER BY updated_at DESC, started_at DESC")
    query.append("LIMIT ?")
    params.append(max(1, min(int(limit), 500)))
    rows = storage.fetchall("\n".join(query), params)
    return [entry for entry in (_serialize_rollout_row(row) for row in rows) if entry]


def create_policy_rollout(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    target_env: str,
    to_release_id: str,
    mode: str,
    canary_percent: Optional[int],
    created_by: Optional[str],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_mode = normalize_rollout_mode(mode)
    normalized_env = str(target_env or "").strip().lower()
    if not normalized_env:
        raise ValueError("target_env is required")

    release = get_policy_release(tenant_id=effective_tenant, release_id=to_release_id)
    if not release:
        raise ValueError("target release not found")
    if str(release.get("policy_id") or "") != str(policy_id):
        raise ValueError("target release policy_id mismatch")
    if str(release.get("target_env") or "").strip().lower() != normalized_env:
        raise ValueError("target release environment mismatch")

    active = get_active_policy_release(
        tenant_id=effective_tenant,
        policy_id=policy_id,
        target_env=normalized_env,
    )
    from_release_id = str((active or {}).get("active_release_id") or "") or None

    normalized_canary_percent = normalize_canary_percent(normalized_mode, canary_percent)
    if normalized_mode == ROLLOUT_MODE_CANARY:
        if not from_release_id:
            raise ValueError("canary rollout requires an existing active release in target environment")
        if from_release_id == str(to_release_id):
            raise ValueError("canary rollout target release is already active")

    storage = get_storage_backend()
    running = storage.fetchone(
        """
        SELECT rollout_id
        FROM policy_rollouts
        WHERE tenant_id = ?
          AND policy_id = ?
          AND target_env = ?
          AND state = ?
        LIMIT 1
        """,
        (effective_tenant, str(policy_id), normalized_env, ROLLOUT_STATE_RUNNING),
    )
    if running:
        raise ValueError("a rollout is already running for this policy/environment")

    now_iso = _utc_now()
    rollout_id = str(uuid.uuid4())

    rollout_state = ROLLOUT_STATE_RUNNING
    completed_at: Optional[str] = None

    if normalized_mode == ROLLOUT_MODE_FULL:
        activate_policy_release(
            tenant_id=effective_tenant,
            release_id=str(to_release_id),
            actor_id=created_by,
        )
        rollout_state = ROLLOUT_STATE_COMPLETED
        completed_at = now_iso

    metadata = {
        "created_reason": "policy rollout",
        "active_release_before": from_release_id,
    }
    storage.execute(
        """
        INSERT INTO policy_rollouts (
            tenant_id, rollout_id, policy_id, target_env,
            from_release_id, to_release_id, mode, canary_percent,
            state, rollback_to_release_id, created_by,
            started_at, completed_at, updated_at, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            rollout_id,
            str(policy_id),
            normalized_env,
            from_release_id,
            str(to_release_id),
            normalized_mode,
            normalized_canary_percent,
            rollout_state,
            None,
            str(created_by or "") or None,
            now_iso,
            completed_at,
            now_iso,
            json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        ),
    )

    _append_rollout_event(
        tenant_id=effective_tenant,
        rollout_id=rollout_id,
        event_type="ROLLOUT_CREATED",
        actor_id=created_by,
        metadata={
            "policy_id": str(policy_id),
            "target_env": normalized_env,
            "from_release_id": from_release_id,
            "to_release_id": str(to_release_id),
            "mode": normalized_mode,
            "canary_percent": normalized_canary_percent,
            "state": rollout_state,
        },
    )
    if rollout_state == ROLLOUT_STATE_COMPLETED:
        _append_rollout_event(
            tenant_id=effective_tenant,
            rollout_id=rollout_id,
            event_type="ROLLOUT_COMPLETED",
            actor_id=created_by,
            metadata={
                "policy_id": str(policy_id),
                "target_env": normalized_env,
                "to_release_id": str(to_release_id),
                "mode": normalized_mode,
            },
        )

    created = get_policy_rollout(tenant_id=effective_tenant, rollout_id=rollout_id)
    if not created:
        raise ValueError("rollout creation failed")
    return created


def promote_policy_rollout(
    *,
    tenant_id: Optional[str],
    rollout_id: str,
    actor_id: Optional[str],
) -> Dict[str, Any]:
    rollout = get_policy_rollout(tenant_id=tenant_id, rollout_id=rollout_id)
    if not rollout:
        raise ValueError("rollout not found")
    if str(rollout.get("state") or "") == ROLLOUT_STATE_COMPLETED:
        return rollout
    if str(rollout.get("state") or "") != ROLLOUT_STATE_RUNNING:
        raise ValueError("only running rollouts can be promoted")

    effective_tenant = resolve_tenant_id(tenant_id)
    to_release_id = str(rollout.get("to_release_id") or "")
    if not to_release_id:
        raise ValueError("rollout is missing to_release_id")

    activate_policy_release(
        tenant_id=effective_tenant,
        release_id=to_release_id,
        actor_id=actor_id,
    )
    now_iso = _utc_now()
    storage = get_storage_backend()
    storage.execute(
        """
        UPDATE policy_rollouts
        SET state = ?, completed_at = ?, updated_at = ?
        WHERE tenant_id = ? AND rollout_id = ?
        """,
        (ROLLOUT_STATE_COMPLETED, now_iso, now_iso, effective_tenant, str(rollout_id)),
    )
    _append_rollout_event(
        tenant_id=effective_tenant,
        rollout_id=str(rollout_id),
        event_type="ROLLOUT_COMPLETED",
        actor_id=actor_id,
        metadata={
            "policy_id": rollout.get("policy_id"),
            "target_env": rollout.get("target_env"),
            "to_release_id": to_release_id,
        },
    )
    promoted = get_policy_rollout(tenant_id=effective_tenant, rollout_id=rollout_id)
    if not promoted:
        raise ValueError("rollout promotion failed")
    return promoted


def rollback_policy_rollout(
    *,
    tenant_id: Optional[str],
    rollout_id: str,
    actor_id: Optional[str],
    rollback_to_release_id: Optional[str] = None,
) -> Dict[str, Any]:
    rollout = get_policy_rollout(tenant_id=tenant_id, rollout_id=rollout_id)
    if not rollout:
        raise ValueError("rollout not found")

    state = str(rollout.get("state") or "").strip().upper()
    if state == ROLLOUT_STATE_ROLLED_BACK:
        return rollout
    if state not in {ROLLOUT_STATE_RUNNING, ROLLOUT_STATE_COMPLETED}:
        raise ValueError("only running/completed rollouts can be rolled back")

    effective_tenant = resolve_tenant_id(tenant_id)
    rollback_target = str(rollback_to_release_id or rollout.get("from_release_id") or "").strip()
    if not rollback_target:
        raise ValueError("rollback target release is required")

    release = get_policy_release(tenant_id=effective_tenant, release_id=rollback_target)
    if not release:
        raise ValueError("rollback target release not found")

    if str(release.get("policy_id") or "") != str(rollout.get("policy_id") or ""):
        raise ValueError("rollback target policy mismatch")
    if str(release.get("target_env") or "").strip().lower() != str(rollout.get("target_env") or "").strip().lower():
        raise ValueError("rollback target environment mismatch")

    activate_policy_release(
        tenant_id=effective_tenant,
        release_id=rollback_target,
        actor_id=actor_id,
    )

    now_iso = _utc_now()
    storage = get_storage_backend()
    storage.execute(
        """
        UPDATE policy_rollouts
        SET state = ?, rollback_to_release_id = ?, completed_at = COALESCE(completed_at, ?), updated_at = ?
        WHERE tenant_id = ? AND rollout_id = ?
        """,
        (
            ROLLOUT_STATE_ROLLED_BACK,
            rollback_target,
            now_iso,
            now_iso,
            effective_tenant,
            str(rollout_id),
        ),
    )
    _append_rollout_event(
        tenant_id=effective_tenant,
        rollout_id=str(rollout_id),
        event_type="ROLLOUT_ROLLED_BACK",
        actor_id=actor_id,
        metadata={
            "policy_id": rollout.get("policy_id"),
            "target_env": rollout.get("target_env"),
            "rollback_to_release_id": rollback_target,
        },
    )
    rolled_back = get_policy_rollout(tenant_id=effective_tenant, rollout_id=rollout_id)
    if not rolled_back:
        raise ValueError("rollout rollback failed")
    return rolled_back


def _release_payload(
    *,
    tenant_id: str,
    policy_id: str,
    target_env: str,
    release_id: str,
    rollout: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    release = get_policy_release(tenant_id=tenant_id, release_id=release_id)
    if not release:
        return None
    snapshot = get_resolved_policy_snapshot(
        tenant_id=tenant_id,
        snapshot_id=str(release.get("snapshot_id") or ""),
    )
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "target_env": target_env,
        "active_release_id": release_id,
        "updated_at": _utc_now(),
        "release": {
            "release_id": release_id,
            "snapshot_id": release.get("snapshot_id"),
            "state": release.get("state"),
            "effective_at": release.get("effective_at"),
            "activated_at": release.get("activated_at"),
            "created_by": release.get("created_by"),
            "change_ticket": release.get("change_ticket"),
            "created_at": release.get("created_at"),
        },
        "snapshot": snapshot,
    }
    if rollout:
        payload["rollout"] = rollout
    return payload


def resolve_effective_policy_release(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    target_env: str,
    rollout_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Resolve effective release for an environment with canary rollout support.
    Falls back to currently active release when no running rollout applies.
    """
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_env = str(target_env or "").strip().lower()
    if not normalized_env:
        raise ValueError("target_env is required")

    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, rollout_id, policy_id, target_env,
               from_release_id, to_release_id, mode, canary_percent,
               state, rollback_to_release_id, created_by,
               started_at, completed_at, updated_at, metadata_json
        FROM policy_rollouts
        WHERE tenant_id = ? AND policy_id = ? AND target_env = ?
          AND state IN (?, ?, ?)
        ORDER BY updated_at DESC, started_at DESC
        LIMIT 1
        """,
        (
            effective_tenant,
            str(policy_id),
            normalized_env,
            ROLLOUT_STATE_RUNNING,
            ROLLOUT_STATE_COMPLETED,
            ROLLOUT_STATE_ROLLED_BACK,
        ),
    )
    rollout = _serialize_rollout_row(row)

    if rollout and str(rollout.get("state") or "") == ROLLOUT_STATE_RUNNING:
        mode = str(rollout.get("mode") or "")
        if mode == ROLLOUT_MODE_CANARY:
            from_release_id = str(rollout.get("from_release_id") or "").strip()
            to_release_id = str(rollout.get("to_release_id") or "").strip()
            if rollout_key and from_release_id and to_release_id:
                bucket = _hash_bucket(
                    tenant_id=effective_tenant,
                    rollout_id=str(rollout.get("rollout_id") or ""),
                    rollout_key=str(rollout_key),
                )
                selected = to_release_id if bucket < int(rollout.get("canary_percent") or 0) else from_release_id
                return _release_payload(
                    tenant_id=effective_tenant,
                    policy_id=str(policy_id),
                    target_env=normalized_env,
                    release_id=selected,
                    rollout={
                        **rollout,
                        "bucket": bucket,
                        "selected_release_id": selected,
                        "selected": selected == to_release_id,
                    },
                )

    active = get_active_policy_release(
        tenant_id=effective_tenant,
        policy_id=str(policy_id),
        target_env=normalized_env,
    )
    if not active:
        return None
    if rollout:
        active_with_rollout = dict(active)
        active_with_rollout["rollout"] = rollout
        return active_with_rollout
    return active
