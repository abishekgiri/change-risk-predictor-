import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.audit.recorder import AuditRecorder
from releasegate.correlation.enforcement import compute_release_correlation_id
from releasegate.config import DB_PATH
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


def test_deploy_gate_blocks_when_correlation_id_missing_by_default(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-504"
    commit_sha = "4444444444444444444444444444444444444444"
    decision = _seed_allowed_decision(repo, 31, issue_key, commit_sha)

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
            "deploy_id": "deploy-no-corr",
            "repo": repo,
            "env": "prod",
            "commit_sha": commit_sha,
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is False
    assert body["status"] == "BLOCKED"
    assert body["reason_code"] == "CORRELATION_ID_MISSING"


def test_deploy_gate_can_derive_correlation_when_policy_override_enabled(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-505"
    commit_sha = "5555555555555555555555555555555555555555"
    decision = _seed_allowed_decision(repo, 32, issue_key, commit_sha)

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
            "deploy_id": "deploy-derive-corr",
            "repo": repo,
            "env": "prod",
            "commit_sha": commit_sha,
            "policy_overrides": {"allow_derive_correlation_id": True},
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is True
    assert body["status"] == "ALLOWED"
    assert body["reason_code"] == "CORRELATION_ALLOWED"
    assert body["correlation_id"]


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
            "policy_overrides": {"allow_derive_correlation_id": True},
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is False
    assert body["status"] == "BLOCKED"
    assert body["reason_code"] == "DEPLOY_COMMIT_MISMATCH"


def test_incident_close_gate_blocks_when_deploy_history_missing():
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-506"
    commit_sha = "6666666666666666666666666666666666666666"
    decision = _seed_allowed_decision(repo, 33, issue_key, commit_sha)
    correlation_id = compute_release_correlation_id(
        issue_key=issue_key,
        repo=repo,
        commit_sha=commit_sha,
        env="prod",
    )

    resp = client.post(
        "/gate/incident/close-check",
        json={
            "tenant_id": "tenant-test",
            "incident_id": "INC-NO-DEPLOY",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": correlation_id,
            "repo": repo,
            "env": "prod",
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is False
    assert body["status"] == "BLOCKED"
    assert body["reason_code"] == "DEPLOY_NOT_FOUND_FOR_CORRELATION"


def test_incident_close_gate_allows_with_valid_deploy_history(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-507"
    commit_sha = "7777777777777777777777777777777777777777"
    decision = _seed_allowed_decision(repo, 34, issue_key, commit_sha)
    correlation_id = compute_release_correlation_id(
        issue_key=issue_key,
        repo=repo,
        commit_sha=commit_sha,
        env="prod",
    )

    monkeypatch.setattr(
        "releasegate.correlation.enforcement.get_active_policy_release",
        lambda **kwargs: {"active_release_id": "release-1"},
    )

    deploy_resp = client.post(
        "/gate/deploy/check",
        json={
            "tenant_id": "tenant-test",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": correlation_id,
            "deploy_id": "deploy-linked",
            "repo": repo,
            "env": "prod",
            "commit_sha": commit_sha,
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert deploy_resp.status_code == 200
    assert deploy_resp.json()["allow"] is True

    incident_resp = client.post(
        "/gate/incident/close-check",
        json={
            "tenant_id": "tenant-test",
            "incident_id": "INC-LINKED",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": correlation_id,
            "deploy_id": "deploy-linked",
            "repo": repo,
            "env": "prod",
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert incident_resp.status_code == 200
    body = incident_resp.json()
    assert body["allow"] is True
    assert body["status"] == "ALLOWED"
    assert body["reason_code"] == "CORRELATION_ALLOWED"


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


def test_deploy_gate_idempotency_replays_same_response(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-508"
    commit_sha = "8888888888888888888888888888888888888888"
    decision = _seed_allowed_decision(repo, 35, issue_key, commit_sha)
    correlation_id = compute_release_correlation_id(
        issue_key=issue_key,
        repo=repo,
        commit_sha=commit_sha,
        env="prod",
    )
    monkeypatch.setattr(
        "releasegate.correlation.enforcement.get_active_policy_release",
        lambda **kwargs: {"active_release_id": "release-1"},
    )

    idem = f"idem-{uuid.uuid4().hex}"
    body = {
        "tenant_id": "tenant-test",
        "decision_id": decision.decision_id,
        "issue_key": issue_key,
        "correlation_id": correlation_id,
        "deploy_id": "deploy-idem-1",
        "repo": repo,
        "env": "prod",
        "commit_sha": commit_sha,
    }
    headers = {
        **jwt_headers(scopes=["enforcement:write"]),
        "Idempotency-Key": idem,
    }
    first = client.post("/gate/deploy/check", json=body, headers=headers)
    second = client.post("/gate/deploy/check", json=body, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()

    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            """
            SELECT status
            FROM idempotency_keys
            WHERE tenant_id = ? AND operation = ? AND idem_key = ?
            """,
            ("tenant-test", "deploy_gate_check", idem),
        ).fetchone()
        assert row is not None
        assert row[0] == "completed"
    finally:
        conn.close()


def test_incident_close_gate_idempotency_key_conflict_returns_409():
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-509"
    decision = _seed_allowed_decision(repo, 36, issue_key, "9999999999999999999999999999999999999999")
    idem = f"idem-{uuid.uuid4().hex}"

    headers = {
        **jwt_headers(scopes=["enforcement:write"]),
        "Idempotency-Key": idem,
    }
    first = client.post(
        "/gate/incident/close-check",
        json={
            "tenant_id": "tenant-test",
            "incident_id": "INC-IDEM-1",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": "corr-a",
            "deploy_id": "deploy-a",
            "repo": repo,
            "env": "prod",
        },
        headers=headers,
    )
    assert first.status_code == 200

    conflict = client.post(
        "/gate/incident/close-check",
        json={
            "tenant_id": "tenant-test",
            "incident_id": "INC-IDEM-2",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": "corr-b",
            "deploy_id": "deploy-b",
            "repo": repo,
            "env": "prod",
        },
        headers=headers,
    )
    assert conflict.status_code == 409


def test_deploy_gate_idempotency_key_conflict_returns_409(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-510"
    commit_sha = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"
    decision = _seed_allowed_decision(repo, 37, issue_key, commit_sha)
    correlation_id = compute_release_correlation_id(
        issue_key=issue_key,
        repo=repo,
        commit_sha=commit_sha,
        env="prod",
    )
    monkeypatch.setattr(
        "releasegate.correlation.enforcement.get_active_policy_release",
        lambda **kwargs: {"active_release_id": "release-1"},
    )

    idem = f"idem-{uuid.uuid4().hex}"
    headers = {
        **jwt_headers(scopes=["enforcement:write"]),
        "Idempotency-Key": idem,
    }
    first = client.post(
        "/gate/deploy/check",
        json={
            "tenant_id": "tenant-test",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": correlation_id,
            "deploy_id": "deploy-idem-a",
            "repo": repo,
            "env": "prod",
            "commit_sha": commit_sha,
        },
        headers=headers,
    )
    assert first.status_code == 200
    conflict = client.post(
        "/gate/deploy/check",
        json={
            "tenant_id": "tenant-test",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": correlation_id,
            "deploy_id": "deploy-idem-b",
            "repo": repo,
            "env": "prod",
            "commit_sha": commit_sha,
        },
        headers=headers,
    )
    assert conflict.status_code == 409


def test_deploy_gate_strict_fail_closed_on_policy_lookup_timeout(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-511"
    commit_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    decision = _seed_allowed_decision(repo, 38, issue_key, commit_sha)
    correlation_id = compute_release_correlation_id(
        issue_key=issue_key,
        repo=repo,
        commit_sha=commit_sha,
        env="prod",
    )

    def _timeout(**kwargs):
        raise TimeoutError("policy lookup timeout")

    monkeypatch.setattr("releasegate.correlation.enforcement.get_active_policy_release", _timeout)

    resp = client.post(
        "/gate/deploy/check",
        json={
            "tenant_id": "tenant-test",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": correlation_id,
            "deploy_id": "deploy-timeout",
            "repo": repo,
            "env": "prod",
            "commit_sha": commit_sha,
            "policy_overrides": {"strict_fail_closed": True},
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is False
    assert body["status"] == "BLOCKED"
    assert body["reason_code"] == "PROVIDER_TIMEOUT"


def test_incident_gate_strict_fail_closed_on_evidence_lookup_timeout(monkeypatch):
    repo = f"corr-{uuid.uuid4().hex[:8]}"
    issue_key = "RG-512"
    commit_sha = "cccccccccccccccccccccccccccccccccccccccc"
    decision = _seed_allowed_decision(repo, 39, issue_key, commit_sha)
    correlation_id = compute_release_correlation_id(
        issue_key=issue_key,
        repo=repo,
        commit_sha=commit_sha,
        env="prod",
    )

    def _timeout(*args, **kwargs):
        raise TimeoutError("graph timeout")

    monkeypatch.setattr("releasegate.evidence.graph.get_decision_evidence_graph", _timeout)

    resp = client.post(
        "/gate/incident/close-check",
        json={
            "tenant_id": "tenant-test",
            "incident_id": "INC-TIMEOUT",
            "decision_id": decision.decision_id,
            "issue_key": issue_key,
            "correlation_id": correlation_id,
            "deploy_id": "deploy-timeout",
            "repo": repo,
            "env": "prod",
            "policy_overrides": {"strict_fail_closed": True},
        },
        headers=jwt_headers(scopes=["enforcement:write"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is False
    assert body["status"] == "BLOCKED"
    assert body["reason_code"] == "PROVIDER_TIMEOUT"
