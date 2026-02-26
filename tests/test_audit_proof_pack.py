import hashlib
import io
import json
import uuid
import zipfile
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.audit.checkpoints import create_override_checkpoint
from releasegate.audit.overrides import record_override
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets, PolicyBinding
from releasegate.server import app
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _policy_hash(policy: dict) -> str:
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bindings_hash(bindings: list[dict]) -> str:
    material = []
    for b in sorted(bindings, key=lambda x: x.get("policy_id", "")):
        material.append(
            {
                "policy_id": b.get("policy_id"),
                "policy_version": b.get("policy_version"),
                "policy_hash": b.get("policy_hash"),
            }
        )
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_audit_proof_pack_contains_evidence(monkeypatch, tmp_path):
    repo = f"proof-{uuid.uuid4().hex[:8]}"
    pr_number = 77
    policy = {
        "policy_id": "PROOF-001",
        "version": "1.0.0",
        "name": "Proof policy",
        "scope": "pull_request",
        "controls": [{"signal": "raw.risk.level", "operator": "==", "value": "HIGH"}],
        "enforcement": {"result": "BLOCK", "message": "x"},
    }
    binding = PolicyBinding(
        policy_id="PROOF-001",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy),
        policy=policy,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])

    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id=f"jira-{repo}-{pr_number}",
        message="BLOCKED: test",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="proof-user",
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
            "policies_requested": ["PROOF-001"],
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["PROOF-1"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    override = record_override(
        repo=repo,
        pr_number=pr_number,
        issue_key="PROOF-1",
        decision_id=stored.decision_id,
        actor="manager-1",
        reason="approved emergency",
    )

    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "proof-secret")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_STORE_DIR", str(tmp_path))
    create_override_checkpoint(
        repo=repo,
        cadence="daily",
        pr=pr_number,
        store_dir=str(tmp_path),
        signing_key="proof-secret",
    )

    resp = client.get(
        f"/audit/proof-pack/{stored.decision_id}",
        params={"format": "json", "tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["proofpack:read", "checkpoint:read", "policy:read"]),
    )
    assert resp.status_code == 200
    body = resp.json()

    assert body["bundle_version"] == "audit_proof_v1"
    assert body["decision_snapshot"]["decision_id"] == stored.decision_id
    assert body["policy_snapshot"][0]["policy_id"] == "PROOF-001"
    assert body["input_snapshot"]["policies_requested"] == ["PROOF-001"]
    assert body["override_snapshot"]["override_id"] == override["override_id"]
    assert body["chain_proof"]["valid"] is True
    assert body["checkpoint_proof"]["exists"] is True
    assert body["checkpoint_proof"]["valid"] is True


def test_audit_proof_pack_zip_format(monkeypatch, tmp_path):
    repo = f"proof-zip-{uuid.uuid4().hex[:8]}"
    pr_number = 78
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="ALLOWED: test",
        policy_bundle_hash="proof-hash",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="proof-user",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={"signal_map": {"repo": repo, "pr_number": pr_number, "diff": {}}, "policies_requested": []},
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["PROOF-2"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "proof-secret")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_STORE_DIR", str(tmp_path))

    resp = client.get(
        f"/audit/proof-pack/{stored.decision_id}",
        params={"format": "zip", "tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["proofpack:read", "checkpoint:read", "policy:read"]),
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert resp.content.startswith(b"PK")


def test_export_proof_alias_includes_manifest_graph_and_replay_request(monkeypatch, tmp_path):
    repo = f"proof-export-{uuid.uuid4().hex[:8]}"
    pr_number = 79
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="ALLOWED: export",
        policy_bundle_hash="proof-hash",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="proof-user",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={"signal_map": {"repo": repo, "pr_number": pr_number, "diff": {}}, "policies_requested": []},
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["PROOF-3"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "proof-secret")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_STORE_DIR", str(tmp_path))

    resp = client.get(
        f"/decisions/{stored.decision_id}/export-proof",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["proofpack:read", "checkpoint:read", "policy:read"]),
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"

    with zipfile.ZipFile(io.BytesIO(resp.content), "r") as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names
        assert "evidence_graph.json" in names
        assert "replay_request.json" in names
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        file_names = {entry.get("filename") for entry in manifest.get("files", [])}
        assert "evidence_graph.json" in file_names
        assert "replay_request.json" in file_names
        evidence_graph = json.loads(zf.read("evidence_graph.json").decode("utf-8"))
        assert "nodes" in evidence_graph
        assert "edges" in evidence_graph
        replay_request = json.loads(zf.read("replay_request.json").decode("utf-8"))
        assert replay_request.get("endpoint") == f"/decisions/{stored.decision_id}/replay"
def test_export_proof_bundle_rejects_cross_tenant_access(monkeypatch, tmp_path):
    repo = f"proof-tenant-{uuid.uuid4().hex[:8]}"
    pr_number = 80
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="ALLOWED: tenant isolation",
        policy_bundle_hash="proof-hash",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="proof-user",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={"signal_map": {"repo": repo, "pr_number": pr_number, "diff": {}}, "policies_requested": []},
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["PROOF-4"]},
        ),
    )
    stored = AuditRecorder.record_with_context(
        decision,
        repo=repo,
        pr_number=pr_number,
        tenant_id="tenant-alpha",
    )
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "proof-secret")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_STORE_DIR", str(tmp_path))

    cross_tenant = client.get(
        f"/decisions/{stored.decision_id}/export-proof",
        params={"tenant_id": "tenant-beta"},
        headers=jwt_headers(
            tenant_id="tenant-alpha",
            roles=["admin"],
            scopes=["proofpack:read", "checkpoint:read", "policy:read"],
        ),
    )
    assert cross_tenant.status_code == 403
    assert (cross_tenant.json().get("detail") or {}).get("error_code") == "TENANT_SCOPE_FORBIDDEN"

    isolated = client.get(
        f"/decisions/{stored.decision_id}/export-proof",
        headers=jwt_headers(
            tenant_id="tenant-beta",
            roles=["admin"],
            scopes=["proofpack:read", "checkpoint:read", "policy:read"],
        ),
    )
    assert isolated.status_code == 404
