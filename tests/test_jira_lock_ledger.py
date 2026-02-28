from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from releasegate.config import DB_PATH
from releasegate.integrations.jira.lock_store import (
    EVENT_LOCK,
    EVENT_OVERRIDE,
    EVENT_OVERRIDE_EXPIRE,
    EVENT_OVERRIDE_STALE,
    EVENT_UNLOCK,
    apply_transition_lock_update,
    expire_override_if_needed,
    get_current_lock_state,
    verify_lock_chain,
)
from releasegate.storage import get_storage_backend
from releasegate.storage.schema import init_db


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def _events(tenant_id: str, issue_key: str):
    storage = get_storage_backend()
    return storage.fetchall(
        """
        SELECT event_type, reason_codes_json, chain_id, seq, prev_hash, event_hash
        FROM jira_lock_events
        WHERE tenant_id = ? AND issue_key = ?
        ORDER BY seq ASC, created_at ASC
        """,
        (tenant_id, issue_key),
    )


def test_lock_then_unlock_records_events_and_updates_current(clean_db):
    tenant = "tenant-a"
    issue = "PROJ-1"

    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=True,
        reason_codes=["POLICY_BLOCKED"],
        decision_id="d1",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="org/repo",
        pr_number=1,
        actor="actor",
    )
    state = get_current_lock_state(tenant_id=tenant, issue_key=issue)
    assert state is not None
    assert state.locked is True
    assert state.lock_reason_codes == ["POLICY_BLOCKED"]

    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=False,
        reason_codes=["POLICY_OK"],
        decision_id="d2",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="org/repo",
        pr_number=1,
        actor="actor",
    )
    state2 = get_current_lock_state(tenant_id=tenant, issue_key=issue)
    assert state2 is not None
    assert state2.locked is False

    events = _events(tenant, issue)
    assert [e["event_type"] for e in events] == [EVENT_LOCK, EVENT_UNLOCK]


def test_override_records_event_and_sets_ttl(clean_db):
    tenant = "tenant-a"
    issue = "PROJ-2"

    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=True,  # ignored for overrides
        reason_codes=["OVERRIDE_APPLIED"],
        decision_id="d3",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="org/repo",
        pr_number=2,
        actor="actor",
        override_expires_at=future,
        override_reason="emergency",
        override_by="actor",
    )
    state = get_current_lock_state(tenant_id=tenant, issue_key=issue)
    assert state is not None
    assert state.locked is False
    assert state.override_expires_at is not None
    assert "emergency" in str(state.override_reason)

    events = _events(tenant, issue)
    assert events[-1]["event_type"] == EVENT_OVERRIDE


def test_override_expiry_clears_override_fields(clean_db):
    tenant = "tenant-a"
    issue = "PROJ-3"

    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=False,
        reason_codes=["OVERRIDE_APPLIED"],
        decision_id="d4",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="org/repo",
        pr_number=3,
        actor="actor",
        override_expires_at=past,
        override_reason="ttl",
        override_by="actor",
    )
    assert expire_override_if_needed(tenant_id=tenant, issue_key=issue, actor="actor") is True

    state = get_current_lock_state(tenant_id=tenant, issue_key=issue)
    assert state is not None
    assert state.locked is True
    assert "OVERRIDE_EXPIRED" in state.lock_reason_codes
    assert state.override_expires_at is None
    assert state.override_reason is None
    assert state.override_by is None


def test_override_expiry_is_idempotent(clean_db):
    tenant = "tenant-a"
    issue = "PROJ-3-IDEMP"

    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=False,
        reason_codes=["OVERRIDE_APPLIED"],
        decision_id="d4-idemp",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="org/repo",
        pr_number=33,
        actor="actor",
        override_expires_at=past,
        override_reason="ttl",
        override_by="actor",
    )

    assert expire_override_if_needed(tenant_id=tenant, issue_key=issue, actor="actor") is True
    assert expire_override_if_needed(tenant_id=tenant, issue_key=issue, actor="actor") is False

    events = _events(tenant, issue)
    expired_events = [row for row in events if row["event_type"] == EVENT_OVERRIDE_EXPIRE]
    assert len(expired_events) == 1


def test_override_staleness_revalidation_clears_override(clean_db):
    tenant = "tenant-a"
    issue = "PROJ-4"
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=False,
        reason_codes=["OVERRIDE_APPLIED"],
        decision_id="d4-override",
        policy_hash="policy-a",
        policy_resolution_hash="policy-a",
        repo="org/repo",
        pr_number=4,
        actor="actor",
        override_expires_at=future,
        override_reason="stale-check",
        override_by="actor",
        context={
            "evaluation_key": "eval-a",
            "policy_hash": "policy-a",
            "risk_hash": "risk-a",
        },
    )

    event_id = apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=True,
        reason_codes=["POLICY_BLOCKED"],
        decision_id="d4-after",
        policy_hash="policy-b",
        policy_resolution_hash="policy-b",
        repo="org/repo",
        pr_number=4,
        actor="actor",
        context={
            "evaluation_key": "eval-b",
            "policy_hash": "policy-b",
            "risk_hash": "risk-b",
        },
    )
    assert event_id is not None

    state = get_current_lock_state(tenant_id=tenant, issue_key=issue)
    assert state is not None
    assert state.locked is True
    assert state.override_expires_at is None
    assert state.override_reason is None
    assert state.override_by is None

    events = _events(tenant, issue)
    assert EVENT_OVERRIDE_STALE in [row["event_type"] for row in events]

    # Replaying the same lock update must not append duplicate stale events.
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=True,
        reason_codes=["POLICY_BLOCKED"],
        decision_id="d4-after",
        policy_hash="policy-b",
        policy_resolution_hash="policy-b",
        repo="org/repo",
        pr_number=4,
        actor="actor",
        context={
            "evaluation_key": "eval-b",
            "policy_hash": "policy-b",
            "risk_hash": "risk-b",
        },
    )
    events_after = _events(tenant, issue)
    stale_events = [row for row in events_after if row["event_type"] == EVENT_OVERRIDE_STALE]
    assert len(stale_events) == 1


def test_lock_event_ledger_is_append_only(clean_db):
    tenant = "tenant-a"
    issue = "PROJ-9"

    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=True,
        reason_codes=["POLICY_BLOCKED"],
        decision_id="d9",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="org/repo",
        pr_number=9,
        actor="actor",
    )

    storage = get_storage_backend()
    with pytest.raises(Exception):
        storage.execute(
            "UPDATE jira_lock_events SET actor = ? WHERE tenant_id = ? AND issue_key = ?",
            ("mut", tenant, issue),
        )
    with pytest.raises(Exception):
        storage.execute(
            "DELETE FROM jira_lock_events WHERE tenant_id = ? AND issue_key = ?",
            (tenant, issue),
        )


def test_lock_event_hash_chain_verifies(clean_db):
    tenant = "tenant-hash"
    issue = "PROJ-42"
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=True,
        reason_codes=["POLICY_BLOCKED"],
        decision_id="d42a",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="org/repo",
        pr_number=42,
        actor="actor",
    )
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=False,
        reason_codes=["POLICY_ALLOWED"],
        decision_id="d42b",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="org/repo",
        pr_number=42,
        actor="actor",
    )

    result = verify_lock_chain(tenant_id=tenant, chain_id=f"jira-lock:{issue}")
    assert result["valid"] is True
    assert result["checked"] == 2
    assert result["head_seq"] == 2

    events = _events(tenant, issue)
    assert all(row.get("chain_id") for row in events)
    assert all(int(row.get("seq") or 0) > 0 for row in events)
    assert all(str(row.get("event_hash") or "").strip() for row in events)
