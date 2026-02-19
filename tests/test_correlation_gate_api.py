import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.audit.recorder import AuditRecorder
from releasegate.correlation.enforcement import compute_release_correlation_id
from releasegate.decision.types import Decision, EnforcementTargets, PolicyBinding
from releasegate.server import app
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _policy_hash(policy: dict) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _bindings_hash(bindings: list[dict]) -> str:
    material = []
    for binding in sorted(bindings, key=lambda x: x.get("policy_id", "")):
        material.append(
            {
                "policy_id": binding.get("policy_id"),
                "policy_version": binding.get("policy_version"),
                "policy_hash": binding.get("policy_hash"),
            }
        )
    payload = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _seed_allowed_decision(repo: str, pr_number: int, issue_key: str, commit_sha: str) -> Decision:
    policy_dict = {
        "policy_id": "RG-CORR-1",
        "version": "1.0.0",
        "name": "Allow low risk",
        "description": "Allow when low risk",
        "scope": "pull_request",
        "enabled": True,
        "controls": [
            {"signal": "raw.risk.level", "operator": "==", "value": "LOW"},
        ],
        "enforcement": {"result": "ALLOW", "message": "Approved"},
        "metadata": {"source": "unit-test"},
    }
    binding = PolicyBinding(
        policy_id="RG-CORR-1",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy_dict),
        policy=policy_dict,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="Policy allowed",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="corr-tester",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
                "risk": {"level": "LOW"},
                "labels": [],
            },
            "policies_requested": ["RG-CORR-1"],
            "issue_key": issue_key,
            "transition_id": "2",
            "environment": "PRODUCTION",
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref=commit_sha,
            external={"jira": [issue_key]},
        ),
    )
    return AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)


def test_deploy_gate_allows_when_decision_and_correlation_match(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-501"
    commit_sha = "abc123abc123abc123abc123abc123abc123abcd"
    decision = _seed_allowed_decision(repo, 28, issue_key, commit_sha)

    monkeypatch.setattr(
        "releasegate.correlation.enforcement.get_active_policy_release",
        lambda **kwargs: {"active_release_id": "release-1"},
    )

    correlation_id = compute_release_correlation_id(
        issue_key=issue_key,
        repo=repo,
        commit_sha=commit_sha,
        env="prod",
    )
    resp = client.post(
        "/gate/deploy/check",
        json={
            "tenant_id": "tenant-test",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": correlation_id,
            "deploy_id": "deploy-1",
            "repo": repo,
            "env": "prod",
            "commit_sha": commit_sha,
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is True
    assert body["status"] == "ALLOWED"
    assert body["reason_code"] == "CORRELATION_ALLOWED"
    assert body["decision_id"] == decision.decision_id


def test_deploy_gate_blocks_on_commit_mismatch(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-502"
    decision = _seed_allowed_decision(repo, 29, issue_key, "1111111111111111111111111111111111111111")

    monkeypatch.setattr(
        "releasegate.correlation.enforcement.get_active_policy_release",
        lambda **kwargs: {"active_release_id": "release-1"},
    )

    resp = client.post(
        "/gate/deploy/check",
        json={
            "tenant_id": "tenant-test",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "deploy_id": "deploy-2",
            "repo": repo,
            "env": "prod",
            "commit_sha": "2222222222222222222222222222222222222222",
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is False
    assert body["status"] == "BLOCKED"
    assert body["reason_code"] == "DEPLOY_COMMIT_MISMATCH"


def test_incident_close_gate_blocks_on_correlation_mismatch():
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-503"
    decision = _seed_allowed_decision(repo, 30, issue_key, "3333333333333333333333333333333333333333")

    resp = client.post(
        "/gate/incident/close-check",
        json={
            "tenant_id": "tenant-test",
            "incident_id": "INC-123",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": "corr_invalid",
            "deploy_id": "deploy-3",
            "repo": repo,
            "env": "prod",
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is False
    assert body["reason_code"] == "CORRELATION_ID_MISMATCH"

