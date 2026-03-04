import os
from datetime import datetime, timezone

import pytest

from releasegate.audit.recorder import AuditRecorder
from releasegate.config import DB_PATH
from releasegate.decision.types import Decision, EnforcementTargets, PolicyBinding
from releasegate.policy.snapshots import (
    build_resolved_policy_snapshot,
    compute_snapshot_policy_hash,
    get_decision_with_snapshot,
    record_policy_decision_binding,
    store_resolved_policy_snapshot,
    verify_decision_snapshot_binding,
)
from releasegate.storage.schema import init_db


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def test_store_resolved_policy_snapshot_is_deduped(clean_db):
    snapshot = build_resolved_policy_snapshot(
        policy_id="releasegate.policy",
        policy_version="1",
        resolution_inputs={"org": "acme", "repo": "acme/service", "env": "prod"},
        resolved_policy={"enforcement": {"mode": "enforce"}, "thresholds": {"risk_max": 0.7}},
    )
    first = store_resolved_policy_snapshot(tenant_id="tenant-test", snapshot=snapshot)
    second = store_resolved_policy_snapshot(tenant_id="tenant-test", snapshot=snapshot)

    assert first["snapshot_id"]
    assert second["snapshot_id"] == first["snapshot_id"]
    assert second["deduped"] is True
    assert first["policy_hash"] == compute_snapshot_policy_hash(snapshot)


def test_audit_recorder_persists_decision_snapshot_binding(clean_db):
    binding = PolicyBinding(
        policy_id="RG-POL-01",
        policy_version="1.0.0",
        policy_hash="sha256:abc123",
        policy={"policy_id": "RG-POL-01", "version": "1.0.0"},
    )
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id="jira:RG-1:2",
        message="allowed",
        policy_bundle_hash="bundle-hash-1",
        reason_code="POLICY_ALLOWED",
        input_snapshot={"issue_key": "RG-1", "transition_id": "2"},
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository="acme/service",
            pr_number=42,
            ref="HEAD",
            external={"jira": ["RG-1"]},
        ),
    )

    stored = AuditRecorder.record_with_context(decision, repo="acme/service", pr_number=42, tenant_id="tenant-test")
    bound = get_decision_with_snapshot(tenant_id="tenant-test", decision_id=stored.decision_id)

    assert bound is not None
    assert bound["decision_id"] == stored.decision_id
    assert bound["issue_key"] == "RG-1"
    assert bound["transition_id"] == "2"
    assert bound["snapshot"]["snapshot"]["policy_hash"] == bound["policy_hash"]

    report = verify_decision_snapshot_binding(tenant_id="tenant-test", decision_id=stored.decision_id)
    assert report["exists"] is True
    assert report["verified"] is True


def test_record_policy_decision_binding_stores_reason_codes(clean_db):
    snapshot = build_resolved_policy_snapshot(
        policy_id="releasegate.policy",
        policy_version="1",
        resolution_inputs={"env": "staging"},
        resolved_policy={"rules": [{"id": "A"}]},
    )
    persisted = store_resolved_policy_snapshot(tenant_id="tenant-test", snapshot=snapshot)
    record = record_policy_decision_binding(
        tenant_id="tenant-test",
        decision_id="decision-123",
        issue_key="RG-9",
        transition_id="10",
        actor_id="user-1",
        snapshot_id=persisted["snapshot_id"],
        policy_hash=persisted["policy_hash"],
        decision="BLOCKED",
        reason_codes=["POLICY_DENIED", "POLICY_DENIED", "RISK_TOO_HIGH"],
        signal_bundle_hash="sha256:input",
    )
    assert record["reason_codes"] == ["POLICY_DENIED", "RISK_TOO_HIGH"]
