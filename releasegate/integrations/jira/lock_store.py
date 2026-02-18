from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


EVENT_LOCK = "LOCK"
EVENT_UNLOCK = "UNLOCK"
EVENT_OVERRIDE = "OVERRIDE"
EVENT_OVERRIDE_EXPIRE = "OVERRIDE_EXPIRE"


@dataclass(frozen=True)
class JiraLockState:
    tenant_id: str
    issue_key: str
    locked: bool
    lock_reason_codes: List[str]
    policy_hash: Optional[str] = None
    policy_resolution_hash: Optional[str] = None
    decision_id: Optional[str] = None
    repo: Optional[str] = None
    pr_number: Optional[int] = None
    locked_by: Optional[str] = None
    override_expires_at: Optional[str] = None
    override_reason: Optional[str] = None
    override_by: Optional[str] = None
    updated_at: Optional[str] = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _json_loads_list(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw if str(x).strip()]
    if isinstance(raw, str):
        try:
            loaded = json.loads(raw)
        except Exception:
            return []
        if isinstance(loaded, list):
            return [str(x) for x in loaded if str(x).strip()]
    return []


def get_current_lock_state(*, tenant_id: str, issue_key: str) -> Optional[JiraLockState]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT *
        FROM jira_issue_locks_current
        WHERE tenant_id = ? AND issue_key = ?
        LIMIT 1
        """,
        (effective_tenant, issue_key),
    )
    if not row:
        return None
    return JiraLockState(
        tenant_id=row.get("tenant_id") or effective_tenant,
        issue_key=row.get("issue_key") or issue_key,
        locked=bool(row.get("locked")),
        lock_reason_codes=_json_loads_list(row.get("lock_reason_codes_json")),
        policy_hash=row.get("policy_hash"),
        policy_resolution_hash=row.get("policy_resolution_hash"),
        decision_id=row.get("decision_id"),
        repo=row.get("repo"),
        pr_number=row.get("pr_number"),
        locked_by=row.get("locked_by"),
        override_expires_at=row.get("override_expires_at"),
        override_reason=row.get("override_reason"),
        override_by=row.get("override_by"),
        updated_at=row.get("updated_at"),
    )


def _append_event(
    *,
    tenant_id: str,
    issue_key: str,
    event_type: str,
    decision_id: Optional[str],
    repo: Optional[str],
    pr_number: Optional[int],
    reason_codes: Sequence[str],
    policy_hash: Optional[str],
    policy_resolution_hash: Optional[str],
    override_expires_at: Optional[str],
    override_reason: Optional[str],
    actor: Optional[str],
    created_at: Optional[str] = None,
) -> str:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    event_id = uuid.uuid4().hex
    storage.execute(
        """
        INSERT INTO jira_lock_events (
            tenant_id, event_id, issue_key, event_type, decision_id, repo, pr_number,
            reason_codes_json, policy_hash, policy_resolution_hash,
            override_expires_at, override_reason, actor, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            event_id,
            issue_key,
            event_type,
            decision_id,
            repo,
            pr_number,
            _json_dumps([str(x) for x in reason_codes if str(x).strip()]),
            policy_hash,
            policy_resolution_hash,
            override_expires_at,
            override_reason,
            actor,
            created_at or _utc_now_iso(),
        ),
    )
    return event_id


def _upsert_current(
    *,
    tenant_id: str,
    issue_key: str,
    locked: bool,
    lock_reason_codes: Sequence[str],
    policy_hash: Optional[str],
    policy_resolution_hash: Optional[str],
    decision_id: Optional[str],
    repo: Optional[str],
    pr_number: Optional[int],
    locked_by: Optional[str],
    override_expires_at: Optional[str],
    override_reason: Optional[str],
    override_by: Optional[str],
    updated_at: Optional[str] = None,
) -> None:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage.execute(
        """
        INSERT INTO jira_issue_locks_current (
            tenant_id, issue_key, locked, lock_reason_codes_json,
            policy_hash, policy_resolution_hash, decision_id, repo, pr_number, locked_by,
            override_expires_at, override_reason, override_by, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, issue_key) DO UPDATE SET
            locked=excluded.locked,
            lock_reason_codes_json=excluded.lock_reason_codes_json,
            policy_hash=excluded.policy_hash,
            policy_resolution_hash=excluded.policy_resolution_hash,
            decision_id=excluded.decision_id,
            repo=excluded.repo,
            pr_number=excluded.pr_number,
            locked_by=excluded.locked_by,
            override_expires_at=excluded.override_expires_at,
            override_reason=excluded.override_reason,
            override_by=excluded.override_by,
            updated_at=excluded.updated_at
        """,
        (
            effective_tenant,
            issue_key,
            1 if locked else 0,
            _json_dumps([str(x) for x in lock_reason_codes if str(x).strip()]),
            policy_hash,
            policy_resolution_hash,
            decision_id,
            repo,
            pr_number,
            locked_by,
            override_expires_at,
            override_reason,
            override_by,
            updated_at or _utc_now_iso(),
        ),
    )


def expire_override_if_needed(*, tenant_id: str, issue_key: str, actor: Optional[str] = None) -> bool:
    """
    If an override TTL has expired, record an OVERRIDE_EXPIRE event and clear
    override fields in the current view.
    """
    state = get_current_lock_state(tenant_id=tenant_id, issue_key=issue_key)
    if not state or not state.override_expires_at:
        return False
    try:
        expires = datetime.fromisoformat(str(state.override_expires_at).replace("Z", "+00:00"))
    except Exception:
        # If it's malformed, clear it and record an expiry event.
        expires = datetime.now(timezone.utc)

    if datetime.now(timezone.utc) <= expires:
        return False

    _append_event(
        tenant_id=tenant_id,
        issue_key=issue_key,
        event_type=EVENT_OVERRIDE_EXPIRE,
        decision_id=state.decision_id,
        repo=state.repo,
        pr_number=state.pr_number,
        reason_codes=["OVERRIDE_EXPIRED"],
        policy_hash=state.policy_hash,
        policy_resolution_hash=state.policy_resolution_hash,
        override_expires_at=state.override_expires_at,
        override_reason=state.override_reason,
        actor=actor,
    )
    _upsert_current(
        tenant_id=tenant_id,
        issue_key=issue_key,
        locked=state.locked,
        lock_reason_codes=state.lock_reason_codes,
        policy_hash=state.policy_hash,
        policy_resolution_hash=state.policy_resolution_hash,
        decision_id=state.decision_id,
        repo=state.repo,
        pr_number=state.pr_number,
        locked_by=state.locked_by,
        override_expires_at=None,
        override_reason=None,
        override_by=None,
    )
    return True


def apply_transition_lock_update(
    *,
    tenant_id: str,
    issue_key: str,
    desired_locked: bool,
    reason_codes: Sequence[str],
    decision_id: Optional[str],
    policy_hash: Optional[str],
    policy_resolution_hash: Optional[str],
    repo: Optional[str],
    pr_number: Optional[int],
    actor: Optional[str],
    override_expires_at: Optional[str] = None,
    override_reason: Optional[str] = None,
    override_by: Optional[str] = None,
    locked_by: str = "releasegate",
) -> Optional[str]:
    """
    Records lock/unlock/override events and updates the current lock state.

    Returns the created event_id if an event was recorded, otherwise None.
    """
    state = get_current_lock_state(tenant_id=tenant_id, issue_key=issue_key)

    # Overrides always record an event and unlock.
    if override_expires_at or override_reason:
        event_id = _append_event(
            tenant_id=tenant_id,
            issue_key=issue_key,
            event_type=EVENT_OVERRIDE,
            decision_id=decision_id,
            repo=repo,
            pr_number=pr_number,
            reason_codes=reason_codes or ["OVERRIDE_APPLIED"],
            policy_hash=policy_hash,
            policy_resolution_hash=policy_resolution_hash,
            override_expires_at=override_expires_at,
            override_reason=override_reason,
            actor=actor,
        )
        _upsert_current(
            tenant_id=tenant_id,
            issue_key=issue_key,
            locked=False,
            lock_reason_codes=[],
            policy_hash=policy_hash,
            policy_resolution_hash=policy_resolution_hash,
            decision_id=decision_id,
            repo=repo,
            pr_number=pr_number,
            locked_by=locked_by,
            override_expires_at=override_expires_at,
            override_reason=override_reason,
            override_by=override_by or actor,
        )
        return event_id

    # Otherwise: record only on a state transition (or first-seen).
    prior_locked = bool(state.locked) if state else None
    if prior_locked is None or bool(prior_locked) != bool(desired_locked):
        event_type = EVENT_LOCK if desired_locked else EVENT_UNLOCK
        event_id = _append_event(
            tenant_id=tenant_id,
            issue_key=issue_key,
            event_type=event_type,
            decision_id=decision_id,
            repo=repo,
            pr_number=pr_number,
            reason_codes=reason_codes,
            policy_hash=policy_hash,
            policy_resolution_hash=policy_resolution_hash,
            override_expires_at=None,
            override_reason=None,
            actor=actor,
        )
        _upsert_current(
            tenant_id=tenant_id,
            issue_key=issue_key,
            locked=desired_locked,
            lock_reason_codes=reason_codes,
            policy_hash=policy_hash,
            policy_resolution_hash=policy_resolution_hash,
            decision_id=decision_id,
            repo=repo,
            pr_number=pr_number,
            locked_by=locked_by,
            override_expires_at=None,
            override_reason=None,
            override_by=None,
        )
        return event_id

    # Keep current view fresh even when no event is emitted.
    _upsert_current(
        tenant_id=tenant_id,
        issue_key=issue_key,
        locked=bool(state.locked) if state else bool(desired_locked),
        lock_reason_codes=state.lock_reason_codes if state else list(reason_codes),
        policy_hash=state.policy_hash if state else policy_hash,
        policy_resolution_hash=state.policy_resolution_hash if state else policy_resolution_hash,
        decision_id=state.decision_id if state else decision_id,
        repo=state.repo if state else repo,
        pr_number=state.pr_number if state else pr_number,
        locked_by=state.locked_by if state else locked_by,
        override_expires_at=state.override_expires_at if state else None,
        override_reason=state.override_reason if state else None,
        override_by=state.override_by if state else None,
    )
    return None

