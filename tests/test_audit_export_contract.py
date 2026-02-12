import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.audit.overrides import record_override
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets
from releasegate.server import app


client = TestClient(app)


def _record_decision(repo: str, pr_number: int) -> Decision:
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id=f"jira-{repo}-{pr_number}",
        message="BLOCKED: policy violation",
        policy_bundle_hash="v1.2.3",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="actor-123",
        reason_code="POLICY_BLOCKED",
        inputs_present={"releasegate_risk": True, "approvals": False},
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["DEMO-1"]},
        ),
    )
    return AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)


def test_audit_export_soc2_contract_has_required_fields():
    repo = f"audit-contract-{uuid.uuid4().hex[:8]}"
    pr_number = 42
    decision = _record_decision(repo, pr_number)
    override = record_override(
        repo=repo,
        pr_number=pr_number,
        issue_key="DEMO-1",
        decision_id=decision.decision_id,
        actor="manager-1",
        reason="approved emergency",
    )

    resp = client.get(
        "/audit/export",
        params={
            "repo": repo,
            "pr": pr_number,
            "tenant_id": "tenant-test",
            "contract": "soc2_v1",
            "include_overrides": "true",
            "verify_chain": "true",
            "format": "json",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["contract"] == "soc2_v1"
    assert isinstance(body["records"], list) and body["records"]

    rec = body["records"][0]
    assert rec["decision_id"] == decision.decision_id
    assert rec["decision"] == "BLOCKED"
    assert rec["reason_code"] == "POLICY_BLOCKED"
    assert rec["human_message"] == "BLOCKED: policy violation"
    assert rec["actor"] == "actor-123"
    assert rec["policy_version"] == "v1.2.3"
    assert rec["inputs_present"] == {"releasegate_risk": True, "approvals": False}
    assert rec["override_id"] == override["override_id"]
    assert rec["chain_verified"] is True


def test_audit_export_soc2_csv_contains_contract_columns():
    repo = f"audit-contract-csv-{uuid.uuid4().hex[:8]}"
    pr_number = 43
    _record_decision(repo, pr_number)

    resp = client.get(
        "/audit/export",
        params={
            "repo": repo,
            "pr": pr_number,
            "tenant_id": "tenant-test",
            "contract": "soc2_v1",
            "format": "csv",
        },
    )
    assert resp.status_code == 200
    text = resp.text
    assert "decision_id" in text
    assert "decision" in text
    assert "reason_code" in text
    assert "human_message" in text
    assert "actor" in text
    assert "policy_version" in text
    assert "inputs_present" in text
    assert "override_id" in text
