from __future__ import annotations

import uuid
from datetime import datetime, timezone

from releasegate.audit.reader import AuditReader
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets
from releasegate.storage import get_storage_backend


def test_audit_recorder_persists_signed_attestation():
    repo = f"attest-{uuid.uuid4().hex[:8]}"
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id=f"jira-{repo}",
        message="BLOCKED: approvals required",
        policy_bundle_hash="bundle-attest",
        evaluation_key=f"{repo}:{uuid.uuid4().hex}",
        actor_id="auditor-test",
        reason_code="POLICY_BLOCKED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "commit_sha": "abc123",
            "risk_score": 89,
            "signals": {"approvals": {"required": 2, "actual": 1}},
        },
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=42,
            ref="abc123",
            external={"jira": ["RG-42"]},
        ),
    )

    recorded = AuditRecorder.record_with_context(decision, repo=repo, pr_number=42, tenant_id="tenant-test")
    assert recorded.attestation_id

    attestation_row = AuditReader.get_attestation_by_decision(recorded.decision_id, tenant_id="tenant-test")
    assert attestation_row is not None
    assert attestation_row["attestation_id"] == recorded.attestation_id
    payload = attestation_row["attestation"]
    assert payload["decision_id"] == recorded.decision_id
    assert payload["tenant_id"] == "tenant-test"
    assert payload["signature"]["algorithm"] == "ed25519"
    signed_hash = str(payload["signature"]["signed_payload_hash"])
    assert signed_hash.startswith("sha256:")
    assert attestation_row["attestation_id"] == signed_hash.split(":", 1)[1]


def test_attestation_storage_is_immutable():
    row = AuditReader.get_attestation_by_decision("decision-attest-001", tenant_id="tenant-test")
    if not row:
        # Ensure at least one row exists for this test by writing a minimal decision.
        repo = f"attest-imm-{uuid.uuid4().hex[:8]}"
        decision = Decision(
            timestamp=datetime.now(timezone.utc),
            release_status="ALLOWED",
            context_id=f"jira-{repo}",
            message="ALLOWED: baseline",
            policy_bundle_hash="bundle-attest",
            evaluation_key=f"{repo}:{uuid.uuid4().hex}",
            actor_id="auditor-test",
            reason_code="POLICY_ALLOWED",
            inputs_present={"releasegate_risk": True},
            input_snapshot={"commit_sha": "abc123"},
            enforcement_targets=EnforcementTargets(repository=repo, pr_number=1, ref="abc123", external={"jira": [repo]}),
        )
        recorded = AuditRecorder.record_with_context(decision, repo=repo, pr_number=1, tenant_id="tenant-test")
        row = AuditReader.get_attestation_by_decision(recorded.decision_id, tenant_id="tenant-test")

    storage = get_storage_backend()
    try:
        storage.execute(
            "UPDATE audit_attestations SET schema_version = ? WHERE tenant_id = ? AND attestation_id = ?",
            ("x", "tenant-test", row["attestation_id"]),
        )
        assert False, "Expected immutable trigger to reject UPDATE"
    except Exception as exc:
        assert "immutable" in str(exc).lower() or "not allowed" in str(exc).lower()
