from __future__ import annotations

import copy
import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.audit.checkpoints import create_override_checkpoint
from releasegate.audit.overrides import record_override
from releasegate.audit.proof_pack_verify import verify_proof_pack_bundle
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.hashing import compute_decision_hash, compute_replay_hash
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


def _build_proof_pack(monkeypatch, tmp_path) -> dict:
    repo = f"verify-proof-{uuid.uuid4().hex[:8]}"
    pr_number = 99
    policy = {
        "policy_id": "VERIFY-001",
        "version": "1.0.0",
        "name": "Verify policy",
        "scope": "pull_request",
        "controls": [{"signal": "raw.risk.level", "operator": "==", "value": "HIGH"}],
        "enforcement": {"result": "BLOCK", "message": "x"},
    }
    binding = PolicyBinding(
        policy_id="VERIFY-001",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy),
        policy=policy,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id=f"jira-{repo}-{pr_number}",
        message="BLOCKED: verify proof-pack",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="verify-user",
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
            "policies_requested": ["VERIFY-001"],
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["VERIFY-1"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    record_override(
        repo=repo,
        pr_number=pr_number,
        issue_key="VERIFY-1",
        decision_id=stored.decision_id,
        actor="manager-1",
        reason="approved emergency",
    )

    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "verify-secret")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID", "verify-key")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_STORE_DIR", str(tmp_path))
    create_override_checkpoint(
        repo=repo,
        cadence="daily",
        pr=pr_number,
        store_dir=str(tmp_path),
        signing_key="verify-secret",
    )

    resp = client.get(
        f"/audit/proof-pack/{stored.decision_id}",
        params={"format": "json", "tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["proofpack:read", "checkpoint:read", "policy:read"]),
    )
    assert resp.status_code == 200
    return resp.json()


def test_verify_proof_pack_valid(monkeypatch, tmp_path):
    bundle = _build_proof_pack(monkeypatch, tmp_path)
    report = verify_proof_pack_bundle(bundle, signing_key="verify-secret")
    assert report["ok"] is True
    assert report["checks"]["ledger"]["ok"] is True
    assert report["checks"]["signature"]["ok"] is True
    assert report["checks"]["hashes"]["ok"] is True
    assert report["checks"]["replay"]["ok"] is True


def test_verify_proof_pack_tampered_snapshot_fails(monkeypatch, tmp_path):
    bundle = _build_proof_pack(monkeypatch, tmp_path)
    tampered = copy.deepcopy(bundle)
    tampered["input_snapshot"]["signal_map"]["repo"] = "tampered/repo"
    report = verify_proof_pack_bundle(tampered, signing_key="verify-secret")
    assert report["ok"] is False
    assert report["error_code"] == "SNAPSHOT_HASH_MISMATCH"


def test_verify_proof_pack_tampered_ledger_fails(monkeypatch, tmp_path):
    bundle = _build_proof_pack(monkeypatch, tmp_path)
    tampered = copy.deepcopy(bundle)
    assert tampered["ledger_segment"]
    tampered["ledger_segment"][0]["previous_hash"] = "f" * 64
    report = verify_proof_pack_bundle(tampered, signing_key="verify-secret")
    assert report["ok"] is False
    assert report["error_code"] == "LEDGER_CHAIN_INVALID"


def test_verify_proof_pack_tampered_signature_fails(monkeypatch, tmp_path):
    bundle = _build_proof_pack(monkeypatch, tmp_path)
    tampered = copy.deepcopy(bundle)
    checkpoint_payload = tampered["checkpoint_snapshot"]["payload"]
    checkpoint_payload["event_count"] = int(checkpoint_payload.get("event_count") or 0) + 1
    report = verify_proof_pack_bundle(tampered, signing_key="verify-secret")
    assert report["ok"] is False
    assert report["error_code"] == "CHECKPOINT_SIGNATURE_INVALID"


def test_verify_proof_pack_replay_mismatch_fails(monkeypatch, tmp_path):
    bundle = _build_proof_pack(monkeypatch, tmp_path)
    tampered = copy.deepcopy(bundle)
    decision_snapshot = tampered["decision_snapshot"]
    decision_snapshot["reason_code"] = "POLICY_ALLOWED"
    decision_hash = compute_decision_hash(
        release_status=str(decision_snapshot.get("release_status") or "UNKNOWN"),
        reason_code=decision_snapshot.get("reason_code"),
        policy_bundle_hash=str(decision_snapshot.get("policy_bundle_hash") or ""),
        inputs_present=decision_snapshot.get("inputs_present") or {},
    )
    decision_snapshot["decision_hash"] = decision_hash
    tampered["integrity"]["decision_hash"] = decision_hash
    tampered["integrity"]["replay_hash"] = compute_replay_hash(
        input_hash=tampered["integrity"]["input_hash"],
        policy_hash=tampered["integrity"]["policy_hash"],
        decision_hash=decision_hash,
    )
    report = verify_proof_pack_bundle(tampered, signing_key="verify-secret")
    assert report["ok"] is False
    assert report["error_code"] == "REPLAY_MISMATCH"
