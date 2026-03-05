import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets, PolicyBinding
from releasegate.server import app
from tests.auth_helpers import jwt_headers


client = TestClient(app)
TENANT_ID = "tenant-phase28"


def _policy_hash(policy: dict) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _bindings_hash(bindings: list[dict]) -> str:
    payload = json.dumps(bindings, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _seed_allowed_decision(tenant_id: str, repo: str, issue_key: str, commit_sha: str) -> Decision:
    policy_dict = {
        "policy_id": "RG-PHASE28",
        "version": "1.0.0",
        "controls": [{"signal": "raw.risk.level", "operator": "==", "value": "LOW"}],
        "enforcement": {"result": "ALLOW", "message": "Approved"},
    }
    binding = PolicyBinding(
        policy_id="RG-PHASE28",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy_dict),
        policy=policy_dict,
    )
    decision = Decision(
        tenant_id=tenant_id,
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"ctx-{uuid.uuid4().hex[:8]}",
        message="Allowed by test policy",
        policy_bundle_hash=_bindings_hash([binding.model_dump(mode="json")]),
        evaluation_key=f"{repo}:{uuid.uuid4().hex}",
        actor_id="phase28-tester",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={"risk_meta": {"releasegate_risk": "LOW", "computed_at": datetime.now(timezone.utc).isoformat()}},
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=42,
            ref=commit_sha,
            external={"jira": [issue_key]},
        ),
    )
    return AuditRecorder.record_with_context(decision, repo=repo, pr_number=42, tenant_id=tenant_id)


def test_gate_deploy_requires_jira_issue_key_in_prod():
    response = client.post(
        "/gates/deploy/evaluate",
        json={
            "tenant_id": TENANT_ID,
            "environment": "production",
            "repo": "org/example",
            "policy_overrides": {"strict_fail_closed": True},
        },
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["enforcement:write"]),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["allow"] is False
    assert payload["reason_code"] == "DEPLOY_JIRA_ISSUE_REQUIRED"


def test_gate_deploy_denies_when_policy_missing_in_strict(monkeypatch):
    repo = f"org/repo-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-2801"
    commit_sha = "a" * 40
    decision = _seed_allowed_decision(tenant_id=TENANT_ID, repo=repo, issue_key=issue_key, commit_sha=commit_sha)

    correlation = client.post(
        "/correlations",
        json={
            "tenant_id": TENANT_ID,
            "jira_issue_key": issue_key,
            "pr_repo": repo,
            "pr_sha": commit_sha,
            "environment": "production",
            "decision_id": decision.decision_id,
            "deploy_id": "deploy-2801",
        },
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["enforcement:write"]),
    )
    assert correlation.status_code == 200
    correlation_id = correlation.json()["correlation_id"]

    monkeypatch.setattr(
        "releasegate.correlation.enforcement.resolve_effective_policy_release",
        lambda **kwargs: None,
    )
    response = client.post(
        "/gates/deploy/evaluate",
        json={
            "tenant_id": TENANT_ID,
            "correlation_id": correlation_id,
            "environment": "production",
            "repo": repo,
            "policy_overrides": {"strict_fail_closed": True},
        },
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["enforcement:write"]),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["allow"] is False
    assert payload["reason_code"] in {"POLICY_RELEASE_MISSING", "POLICY_NOT_LOADED", "POLICY_MISSING"}


def test_gate_incident_close_denies_without_postmortem_link():
    correlation = client.post(
        "/correlations",
        json={
            "tenant_id": TENANT_ID,
            "jira_issue_key": "RG-2802",
            "pr_repo": "org/incident",
            "pr_sha": "b" * 40,
            "environment": "production",
            "incident_id": "INC-1001",
        },
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["enforcement:write"]),
    )
    assert correlation.status_code == 200
    correlation_id = correlation.json()["correlation_id"]

    response = client.post(
        "/gates/incident/evaluate",
        json={
            "tenant_id": TENANT_ID,
            "incident_id": "INC-1001",
            "correlation_id": correlation_id,
            "policy_overrides": {"incident_close_requires_postmortem": True},
        },
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["enforcement:write"]),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["allow"] is False
    assert payload["reason_code"] == "POSTMORTEM_REQUIRED"


def test_correlation_attach_idempotent():
    created = client.post(
        "/correlations",
        json={
            "tenant_id": TENANT_ID,
            "jira_issue_key": "RG-2803",
            "pr_repo": "org/idempotent",
            "pr_sha": "c" * 40,
            "environment": "staging",
        },
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["enforcement:write"]),
    )
    assert created.status_code == 200
    record = created.json()
    correlation_id = record["correlation_id"]

    first_attach = client.post(
        f"/correlations/{correlation_id}/attach",
        json={
            "tenant_id": TENANT_ID,
            "deploy_id": "deploy-2803",
            "incident_id": "INC-2803",
        },
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["enforcement:write"]),
    )
    assert first_attach.status_code == 200
    first_payload = first_attach.json()

    second_attach = client.post(
        f"/correlations/{correlation_id}/attach",
        json={
            "tenant_id": TENANT_ID,
            "deploy_id": "deploy-2803",
            "incident_id": "INC-2803",
        },
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["enforcement:write"]),
    )
    assert second_attach.status_code == 200
    second_payload = second_attach.json()
    assert first_payload["correlation_id"] == second_payload["correlation_id"]
    assert first_payload["deploy_id"] == second_payload["deploy_id"] == "deploy-2803"
    assert first_payload["incident_id"] == second_payload["incident_id"] == "INC-2803"
    assert first_payload["updated_at"] == second_payload["updated_at"]
