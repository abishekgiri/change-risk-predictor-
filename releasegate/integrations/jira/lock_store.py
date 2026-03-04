from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


EVENT_LOCK = "LOCK"
EVENT_UNLOCK = "UNLOCK"
EVENT_OVERRIDE = "OVERRIDE"
EVENT_OVERRIDE_EXPIRE = "OVERRIDE_EXPIRE"
EVENT_OVERRIDE_STALE = "OVERRIDE_STALE"
LOCK_CHAIN_ROOT_HASH = "0" * 64


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


def _parse_iso_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value or "").strip()
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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


def _json_loads_obj(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        try:
            loaded = json.loads(text)
        except Exception:
            return {}
        return dict(loaded) if isinstance(loaded, dict) else {}
    return {}


def _default_chain_id(issue_key: str) -> str:
    return f"jira-lock:{issue_key}"


def _canonical_event_payload(
    *,
    tenant_id: str,
    chain_id: str,
    seq: int,
    issue_key: str,
    event_type: str,
    decision_id: Optional[str],
    repo: Optional[str],
    pr_number: Optional[int],
    reason_codes: Sequence[str],
    policy_hash: Optional[str],
    policy_resolution_hash: Optional[str],
    ttl_seconds: Optional[int],
    expires_at: Optional[str],
    justification: Optional[str],
    actor: Optional[str],
    context: Optional[Dict[str, Any]],
    created_at: str,
    prev_hash: str,
) -> Dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "chain_id": chain_id,
        "seq": int(seq),
        "issue_key": issue_key,
        "event_type": event_type,
        "decision_id": decision_id,
        "repo": repo,
        "pr_number": pr_number,
        "reason_codes": [str(x) for x in reason_codes if str(x).strip()],
        "policy_hash": policy_hash,
        "policy_resolution_hash": policy_resolution_hash,
        "ttl_seconds": int(ttl_seconds) if ttl_seconds is not None else None,
        "expires_at": expires_at,
        "justification": justification,
        "actor": actor,
        "context": context or {},
        "created_at": created_at,
        "prev_hash": prev_hash,
    }


def _compute_event_hash(prev_hash: str, canonical_payload: Dict[str, Any]) -> str:
    canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256()
    digest.update((prev_hash or LOCK_CHAIN_ROOT_HASH).encode("utf-8"))
    digest.update(b":")
    digest.update(canonical)
    return digest.hexdigest()


def _get_chain_tip(*, tenant_id: str, chain_id: str) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    return storage.fetchone(
        """
        SELECT seq, event_hash, created_at
        FROM jira_lock_events
        WHERE tenant_id = ? AND chain_id = ? AND seq IS NOT NULL
        ORDER BY seq DESC
        LIMIT 1
        """,
        (effective_tenant, chain_id),
    )


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


def _latest_override_binding(*, tenant_id: str, issue_key: str) -> Dict[str, str]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT policy_hash, policy_resolution_hash, context_json
        FROM jira_lock_events
        WHERE tenant_id = ? AND issue_key = ? AND event_type = ?
        ORDER BY seq DESC, created_at DESC
        LIMIT 1
        """,
        (effective_tenant, issue_key, EVENT_OVERRIDE),
    )
    if not row:
        return {}
    context = _json_loads_obj(row.get("context_json"))
    return {
        "evaluation_key": str(context.get("evaluation_key") or "").strip(),
        "policy_hash": str(
            context.get("policy_hash")
            or row.get("policy_hash")
            or row.get("policy_resolution_hash")
            or ""
        ).strip(),
        "risk_hash": str(context.get("risk_hash") or "").strip(),
    }


def _current_override_binding(
    *,
    policy_hash: Optional[str],
    policy_resolution_hash: Optional[str],
    context: Optional[Dict[str, Any]],
) -> Dict[str, str]:
    normalized_context = context if isinstance(context, dict) else {}
    return {
        "evaluation_key": str(normalized_context.get("evaluation_key") or "").strip(),
        "policy_hash": str(
            normalized_context.get("policy_hash")
            or policy_hash
            or policy_resolution_hash
            or ""
        ).strip(),
        "risk_hash": str(normalized_context.get("risk_hash") or "").strip(),
    }


def _override_freshness_mismatches(
    *,
    expected: Dict[str, str],
    actual: Dict[str, str],
) -> Dict[str, Dict[str, str]]:
    mismatches: Dict[str, Dict[str, str]] = {}
    for key in ("evaluation_key", "policy_hash", "risk_hash"):
        expected_value = str(expected.get(key) or "").strip()
        if not expected_value:
            continue
        actual_value = str(actual.get(key) or "").strip()
        if expected_value != actual_value:
            mismatches[key] = {
                "expected": expected_value,
                "actual": actual_value,
            }
    return mismatches


def _revalidate_override_freshness(
    *,
    tenant_id: str,
    issue_key: str,
    state: Optional[JiraLockState],
    policy_hash: Optional[str],
    policy_resolution_hash: Optional[str],
    actor: Optional[str],
    context: Optional[Dict[str, Any]],
) -> tuple[Optional[JiraLockState], Optional[str]]:
    if not state or not state.override_expires_at:
        return state, None
    expected = _latest_override_binding(tenant_id=tenant_id, issue_key=issue_key)
    if not expected:
        return state, None
    actual = _current_override_binding(
        policy_hash=policy_hash,
        policy_resolution_hash=policy_resolution_hash,
        context=context,
    )
    mismatches = _override_freshness_mismatches(expected=expected, actual=actual)
    if not mismatches:
        return state, None

    event_id = _append_event(
        tenant_id=tenant_id,
        issue_key=issue_key,
        event_type=EVENT_OVERRIDE_STALE,
        decision_id=state.decision_id,
        repo=state.repo,
        pr_number=state.pr_number,
        reason_codes=["OVERRIDE_STALE"],
        policy_hash=policy_hash or state.policy_hash,
        policy_resolution_hash=policy_resolution_hash or state.policy_resolution_hash,
        override_expires_at=state.override_expires_at,
        override_reason=state.override_reason,
        actor=actor,
        context={
            "override_freshness_mismatches": mismatches,
            "expected_binding": expected,
            "actual_binding": actual,
        },
    )
    return (
        replace(
            state,
            override_expires_at=None,
            override_reason=None,
            override_by=None,
        ),
        event_id,
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
    chain_id: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    expires_at: Optional[str] = None,
    justification: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    created_at: Optional[str] = None,
) -> str:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    effective_chain_id = (chain_id or _default_chain_id(issue_key)).strip()
    event_context = context or {}
    max_attempts = 5
    for _attempt in range(max_attempts):
        tip = _get_chain_tip(tenant_id=effective_tenant, chain_id=effective_chain_id)
        prior_seq = int(tip.get("seq") or 0) if tip else 0
        prev_hash = str(tip.get("event_hash") or LOCK_CHAIN_ROOT_HASH) if tip else LOCK_CHAIN_ROOT_HASH
        seq = prior_seq + 1
        now = created_at or _utc_now_iso()
        canonical_payload = _canonical_event_payload(
            tenant_id=effective_tenant,
            chain_id=effective_chain_id,
            seq=seq,
            issue_key=issue_key,
            event_type=event_type,
            decision_id=decision_id,
            repo=repo,
            pr_number=pr_number,
            reason_codes=reason_codes,
            policy_hash=policy_hash,
            policy_resolution_hash=policy_resolution_hash,
            ttl_seconds=ttl_seconds,
            expires_at=expires_at or override_expires_at,
            justification=justification or override_reason,
            actor=actor,
            context=event_context,
            created_at=now,
            prev_hash=prev_hash,
        )
        event_hash = _compute_event_hash(prev_hash, canonical_payload)
        event_id = uuid.uuid4().hex
        try:
            storage.execute(
                """
                INSERT INTO jira_lock_events (
                    tenant_id, event_id, issue_key, event_type, decision_id, repo, pr_number,
                    reason_codes_json, policy_hash, policy_resolution_hash,
                    override_expires_at, override_reason, actor, created_at,
                    chain_id, seq, prev_hash, event_hash, ttl_seconds, expires_at, justification, context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    now,
                    effective_chain_id,
                    seq,
                    prev_hash,
                    event_hash,
                    int(ttl_seconds) if ttl_seconds is not None else None,
                    expires_at or override_expires_at,
                    justification or override_reason,
                    _json_dumps(event_context),
                ),
            )
            return event_id
        except Exception as exc:
            lowered = str(exc).lower()
            if "unique" in lowered and "jira_lock_events" in lowered:
                # Concurrent writer advanced chain tip; retry with fresh prev hash/seq.
                continue
            raise
    raise RuntimeError("Unable to append jira lock event after retries due to concurrent ledger updates")


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
        locked=True,
        lock_reason_codes=["OVERRIDE_EXPIRED"],
        policy_hash=state.policy_hash,
        policy_resolution_hash=state.policy_resolution_hash,
        decision_id=state.decision_id,
        repo=state.repo,
        pr_number=state.pr_number,
        locked_by=actor or state.locked_by,
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
    chain_id: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    justification: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    locked_by: str = "releasegate",
) -> Optional[str]:
    """
    Records lock/unlock/override events and updates the current lock state.

    Returns the created event_id if an event was recorded, otherwise None.
    """
    state = get_current_lock_state(tenant_id=tenant_id, issue_key=issue_key)
    stale_event_id: Optional[str] = None
    if not (override_expires_at or override_reason):
        state, stale_event_id = _revalidate_override_freshness(
            tenant_id=tenant_id,
            issue_key=issue_key,
            state=state,
            policy_hash=policy_hash,
            policy_resolution_hash=policy_resolution_hash,
            actor=actor,
            context=context,
        )

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
            chain_id=chain_id,
            ttl_seconds=ttl_seconds,
            expires_at=override_expires_at,
            justification=justification or override_reason,
            context=context,
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
            chain_id=chain_id,
            context=context,
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
        policy_hash=policy_hash if policy_hash is not None else (state.policy_hash if state else None),
        policy_resolution_hash=(
            policy_resolution_hash
            if policy_resolution_hash is not None
            else (state.policy_resolution_hash if state else None)
        ),
        decision_id=decision_id if decision_id is not None else (state.decision_id if state else None),
        repo=repo if repo is not None else (state.repo if state else None),
        pr_number=pr_number if pr_number is not None else (state.pr_number if state else None),
        locked_by=locked_by if locked_by is not None else (state.locked_by if state else None),
        override_expires_at=state.override_expires_at if state else None,
        override_reason=state.override_reason if state else None,
        override_by=state.override_by if state else None,
    )
    return stale_event_id


def list_lock_chain_events(
    *,
    tenant_id: str,
    chain_id: str,
    from_seq: Optional[int] = None,
    to_seq: Optional[int] = None,
) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    query = """
        SELECT *
        FROM jira_lock_events
        WHERE tenant_id = ? AND chain_id = ? AND seq IS NOT NULL
    """
    params: List[Any] = [effective_tenant, chain_id]
    if from_seq is not None:
        query += " AND seq >= ?"
        params.append(int(from_seq))
    if to_seq is not None:
        query += " AND seq <= ?"
        params.append(int(to_seq))
    query += " ORDER BY seq ASC"
    return storage.fetchall(query, params)


def compute_lock_chain_root(
    *,
    tenant_id: str,
    chain_id: str,
    up_to: Optional[Any] = None,
) -> Dict[str, Any]:
    rows = list_lock_chain_events(tenant_id=tenant_id, chain_id=chain_id)
    cutoff = _parse_iso_datetime(up_to) if up_to is not None else None
    if cutoff is not None:
        filtered = []
        for row in rows:
            created_at_raw = row.get("created_at")
            if not created_at_raw:
                continue
            try:
                created_at = _parse_iso_datetime(created_at_raw)
            except Exception:
                continue
            if created_at <= cutoff:
                filtered.append(row)
        rows = filtered

    expected_prev = LOCK_CHAIN_ROOT_HASH
    expected_seq = 1
    checked = 0
    first_event_at: Optional[str] = None
    last_event_at: Optional[str] = None
    head_hash = LOCK_CHAIN_ROOT_HASH
    head_seq = 0
    for row in rows:
        checked += 1
        row_seq = int(row.get("seq") or 0)
        if row_seq != expected_seq:
            return {
                "valid_chain": False,
                "reason": "sequence gap",
                "checked": checked,
                "chain_id": chain_id,
                "tenant_id": resolve_tenant_id(tenant_id),
                "at_seq": row_seq,
                "expected_seq": expected_seq,
            }
        prev_hash = str(row.get("prev_hash") or "")
        if prev_hash != expected_prev:
            return {
                "valid_chain": False,
                "reason": "prev_hash mismatch",
                "checked": checked,
                "chain_id": chain_id,
                "tenant_id": resolve_tenant_id(tenant_id),
                "at_seq": row_seq,
            }
        canonical_payload = _canonical_event_payload(
            tenant_id=resolve_tenant_id(tenant_id),
            chain_id=chain_id,
            seq=row_seq,
            issue_key=str(row.get("issue_key") or ""),
            event_type=str(row.get("event_type") or ""),
            decision_id=row.get("decision_id"),
            repo=row.get("repo"),
            pr_number=row.get("pr_number"),
            reason_codes=_json_loads_list(row.get("reason_codes_json")),
            policy_hash=row.get("policy_hash"),
            policy_resolution_hash=row.get("policy_resolution_hash"),
            ttl_seconds=row.get("ttl_seconds"),
            expires_at=row.get("expires_at") or row.get("override_expires_at"),
            justification=row.get("justification") or row.get("override_reason"),
            actor=row.get("actor"),
            context=_json_loads_obj(row.get("context_json")),
            created_at=str(row.get("created_at") or ""),
            prev_hash=prev_hash,
        )
        expected_event_hash = _compute_event_hash(prev_hash, canonical_payload)
        actual_event_hash = str(row.get("event_hash") or "")
        if expected_event_hash != actual_event_hash:
            return {
                "valid_chain": False,
                "reason": "event_hash mismatch",
                "checked": checked,
                "chain_id": chain_id,
                "tenant_id": resolve_tenant_id(tenant_id),
                "at_seq": row_seq,
            }
        if first_event_at is None:
            first_event_at = row.get("created_at")
        last_event_at = row.get("created_at")
        head_hash = actual_event_hash
        head_seq = row_seq
        expected_prev = actual_event_hash
        expected_seq += 1

    return {
        "valid_chain": True,
        "reason": None,
        "tenant_id": resolve_tenant_id(tenant_id),
        "chain_id": chain_id,
        "event_count": checked,
        "head_seq": head_seq,
        "head_hash": head_hash if checked else LOCK_CHAIN_ROOT_HASH,
        "first_event_at": first_event_at,
        "last_event_at": last_event_at,
    }


def verify_lock_chain(
    *,
    tenant_id: str,
    chain_id: str,
    from_seq: Optional[int] = None,
    to_seq: Optional[int] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    start_seq = int(from_seq) if from_seq is not None else None
    end_seq = int(to_seq) if to_seq is not None else None

    expected_prev = LOCK_CHAIN_ROOT_HASH
    expected_seq = 1
    if start_seq and start_seq > 1:
        prev_row = storage.fetchone(
            """
            SELECT seq, event_hash
            FROM jira_lock_events
            WHERE tenant_id = ? AND chain_id = ? AND seq = ?
            LIMIT 1
            """,
            (effective_tenant, chain_id, start_seq - 1),
        )
        if not prev_row:
            return {
                "valid": False,
                "reason": "missing previous sequence",
                "tenant_id": effective_tenant,
                "chain_id": chain_id,
                "checked": 0,
                "expected_prev_seq": start_seq - 1,
            }
        expected_prev = str(prev_row.get("event_hash") or LOCK_CHAIN_ROOT_HASH)
        expected_seq = start_seq

    rows = list_lock_chain_events(
        tenant_id=effective_tenant,
        chain_id=chain_id,
        from_seq=start_seq,
        to_seq=end_seq,
    )
    checked = 0
    first_event_at: Optional[str] = None
    last_event_at: Optional[str] = None
    head_hash = expected_prev
    head_seq = (expected_seq - 1) if rows else 0

    for row in rows:
        checked += 1
        row_seq = int(row.get("seq") or 0)
        if row_seq != expected_seq:
            return {
                "valid": False,
                "reason": "sequence gap",
                "tenant_id": effective_tenant,
                "chain_id": chain_id,
                "checked": checked,
                "expected_seq": expected_seq,
                "actual_seq": row_seq,
                "event_id": row.get("event_id"),
            }
        prev_hash = str(row.get("prev_hash") or "")
        if prev_hash != expected_prev:
            return {
                "valid": False,
                "reason": "prev_hash mismatch",
                "tenant_id": effective_tenant,
                "chain_id": chain_id,
                "checked": checked,
                "expected_prev_hash": expected_prev,
                "actual_prev_hash": prev_hash,
                "event_id": row.get("event_id"),
            }
        canonical_payload = _canonical_event_payload(
            tenant_id=effective_tenant,
            chain_id=chain_id,
            seq=row_seq,
            issue_key=str(row.get("issue_key") or ""),
            event_type=str(row.get("event_type") or ""),
            decision_id=row.get("decision_id"),
            repo=row.get("repo"),
            pr_number=row.get("pr_number"),
            reason_codes=_json_loads_list(row.get("reason_codes_json")),
            policy_hash=row.get("policy_hash"),
            policy_resolution_hash=row.get("policy_resolution_hash"),
            ttl_seconds=row.get("ttl_seconds"),
            expires_at=row.get("expires_at") or row.get("override_expires_at"),
            justification=row.get("justification") or row.get("override_reason"),
            actor=row.get("actor"),
            context=_json_loads_obj(row.get("context_json")),
            created_at=str(row.get("created_at") or ""),
            prev_hash=prev_hash,
        )
        expected_event_hash = _compute_event_hash(prev_hash, canonical_payload)
        actual_event_hash = str(row.get("event_hash") or "")
        if expected_event_hash != actual_event_hash:
            return {
                "valid": False,
                "reason": "event_hash mismatch",
                "tenant_id": effective_tenant,
                "chain_id": chain_id,
                "checked": checked,
                "expected_event_hash": expected_event_hash,
                "actual_event_hash": actual_event_hash,
                "event_id": row.get("event_id"),
            }
        if first_event_at is None:
            first_event_at = row.get("created_at")
        last_event_at = row.get("created_at")
        head_hash = actual_event_hash
        head_seq = row_seq
        expected_prev = actual_event_hash
        expected_seq += 1

    return {
        "valid": True,
        "tenant_id": effective_tenant,
        "chain_id": chain_id,
        "checked": checked,
        "head_seq": head_seq,
        "head_hash": head_hash,
        "event_count": checked,
        "first_event_at": first_event_at,
        "last_event_at": last_event_at,
        "from_seq": start_seq,
        "to_seq": end_seq,
    }


def verify_all_lock_chains(*, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    if tenant_id:
        effective_tenant = resolve_tenant_id(tenant_id)
        rows = storage.fetchall(
            """
            SELECT DISTINCT tenant_id, chain_id
            FROM jira_lock_events
            WHERE tenant_id = ? AND chain_id IS NOT NULL
            ORDER BY chain_id ASC
            """,
            (effective_tenant,),
        )
    else:
        rows = storage.fetchall(
            """
            SELECT DISTINCT tenant_id, chain_id
            FROM jira_lock_events
            WHERE chain_id IS NOT NULL
            ORDER BY tenant_id ASC, chain_id ASC
            """
        )
    results = []
    all_valid = True
    for row in rows:
        effective_tenant = resolve_tenant_id(str(row.get("tenant_id") or "default"))
        chain_id = str(row.get("chain_id") or "").strip()
        if not chain_id:
            continue
        result = verify_lock_chain(tenant_id=effective_tenant, chain_id=chain_id)
        results.append(result)
        if not result.get("valid", False):
            all_valid = False
    return {
        "valid": all_valid,
        "checked_chains": len(results),
        "results": results,
    }
