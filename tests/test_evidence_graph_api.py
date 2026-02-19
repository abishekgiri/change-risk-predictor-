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


def _seed_decision(repo: str, pr_number: int, issue_key: str) -> Decision:
    policy_dict = {
        "policy_id": "RG-GRAPH-1",
        "version": "1.0.0",
        "name": "Warn on medium",
        "description": "Warn when risk is medium",
        "scope": "pull_request",
        "enabled": True,
        "controls": [
            {"signal": "raw.risk.level", "operator": "==", "value": "MEDIUM"},
        ],
        "enforcement": {"result": "WARN", "message": "Needs review"},
        "metadata": {"source": "unit-test"},
    }
    binding = PolicyBinding(
        policy_id="RG-GRAPH-1",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy_dict),
        policy=policy_dict,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="CONDITIONAL",
        context_id=f"jira-{repo}-{pr_number}",
        message="Conditional approval",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="graph-tester",
        reason_code="POLICY_CONDITIONAL",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
                "risk": {"level": "MEDIUM"},
                "labels": [],
            },
            "policies_requested": ["RG-GRAPH-1"],
            "issue_key": issue_key,
            "transition_id": "2",
            "environment": "PRODUCTION",
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="abc123def456",
            external={"jira": [issue_key]},
        ),
    )
    return AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)


def test_evidence_graph_and_explain_endpoints():
    repo = f"graph-{uuid.uuid4().hex[:8]}"
    pr_number = 11
    issue_key = "RG-401"
    stored = _seed_decision(repo, pr_number, issue_key)

    replay_resp = client.post(
        f"/decisions/{stored.decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert replay_resp.status_code == 200
    proof_pack_resp = client.get(
        f"/audit/proof-pack/{stored.decision_id}",
        params={"tenant_id": "tenant-test", "format": "json"},
        headers=jwt_headers(scopes=["proofpack:read"]),
    )
    assert proof_pack_resp.status_code == 200
    override_resp = client.post(
        "/audit/overrides",
        params={"tenant_id": "tenant-test"},
        headers={
            **jwt_headers(scopes=["override:write"], roles=["admin"]),
            "Idempotency-Key": f"override-{uuid.uuid4().hex}",
        },
        json={
            "repo": repo,
            "pr_number": pr_number,
            "issue_key": issue_key,
            "decision_id": stored.decision_id,
            "reason": "Emergency override justified by approved incident mitigation plan.",
            "ttl_seconds": 3600,
            "target_type": "pr",
            "target_id": f"{repo}#{pr_number}",
        },
    )
    assert override_resp.status_code == 200

    graph_resp = client.get(
        f"/decisions/{stored.decision_id}/evidence-graph",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert graph_resp.status_code == 200
    graph = graph_resp.json()
    node_types = {node.get("type") for node in graph.get("nodes", [])}
    assert "DECISION" in node_types
    assert "POLICY_SNAPSHOT" in node_types
    assert "SIGNAL_BUNDLE" in node_types
    assert "PULL_REQUEST" in node_types
    assert "JIRA_ISSUE" in node_types
    assert "REPLAY" in node_types
    assert "ARTIFACT" in node_types
    assert "OVERRIDE" in node_types
    assert graph.get("edges")
    edge_types = {edge.get("type") for edge in graph.get("edges", [])}
    assert "PRODUCED_ARTIFACT" in edge_types
    assert "OVERRIDDEN_BY" in edge_types

    explain_resp = client.get(
        f"/decisions/{stored.decision_id}/explain",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert explain_resp.status_code == 200
    explanation = explain_resp.json()
    assert explanation.get("decision_id") == stored.decision_id
    assert "Decision" in explanation.get("summary", "")
    assert explanation.get("graph", {}).get("nodes")
    assert explanation.get("evidence", {}).get("replays")
    assert explanation.get("evidence", {}).get("artifacts")
    assert explanation.get("evidence", {}).get("overrides")
