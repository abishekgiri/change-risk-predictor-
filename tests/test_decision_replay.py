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


def test_replay_endpoint_recomputes_status_and_policy_hash():
    repo = f"replay-{uuid.uuid4().hex[:8]}"
    pr_number = 101
    policy_dict = {
        "policy_id": "RG-POL-1",
        "version": "1.0.0",
        "name": "Block high risk",
        "description": "Block when risk is high",
        "scope": "pull_request",
        "enabled": True,
        "controls": [
            {"signal": "raw.risk.level", "operator": "==", "value": "HIGH"},
        ],
        "enforcement": {"result": "BLOCK", "message": "High risk blocked"},
        "metadata": {"source": "unit-test"},
    }
    binding = PolicyBinding(
        policy_id="RG-POL-1",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy_dict),
        policy=policy_dict,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])

    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id=f"jira-{repo}-{pr_number}",
        message="Policy Check (Open -> Ready): BLOCKED",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="actor-123",
        reason_code="POLICY_BLOCKED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
                "risk": {"level": "HIGH"},
                "labels": [],
            },
            "policies_requested": ["RG-POL-1"],
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["RG-1"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    resp = client.post(
        f"/decisions/{stored.decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision_id"] == stored.decision_id
    assert body["attestation_id"] == stored.attestation_id
    assert body["original_status"] == "BLOCKED"
    assert body["replay_status"] == "BLOCKED"
    assert body["status_match"] is True
    assert body["policy_hash_match"] is True
    assert body["input_hash_match"] is True
    assert body["decision_hash_match"] is True
    assert body["replay_hash_match"] is True
    assert body["matches_original"] is True
    assert body["mismatch_reason"] is None
    assert body["triggered_policies"] == ["RG-POL-1"]
    assert body["repo"] == repo
    assert body["pr_number"] == pr_number


def test_replay_endpoint_requires_policy_bindings():
    repo = f"replay-missing-bindings-{uuid.uuid4().hex[:8]}"
    pr_number = 102
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="SKIPPED",
        context_id=f"jira-{repo}-{pr_number}",
        message="SKIPPED: invalid policy references",
        policy_bundle_hash="any",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        reason_code="INVALID_POLICY_REFERENCE",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
            },
            "policies_requested": ["RG-POL-1"],
        },
        policy_bindings=[],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["RG-2"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    resp = client.post(
        f"/decisions/{stored.decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert resp.status_code == 422
    detail = resp.json().get("detail", "")
    assert "no policy bindings" in detail.lower()
