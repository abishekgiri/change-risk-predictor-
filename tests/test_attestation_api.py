from __future__ import annotations

from fastapi.testclient import TestClient

from releasegate.attestation.service import build_attestation_from_bundle
from releasegate.attestation.types import DecisionBundle
from releasegate.server import app


client = TestClient(app)


def _sample_attestation() -> dict:
    bundle = DecisionBundle(
        tenant_id="tenant-test",
        decision_id="decision-api-verify-001",
        repo="org/api",
        pr_number=11,
        commit_sha="abc123",
        policy_version="1.0.0",
        policy_hash="policy-hash",
        policy_bundle_hash="bundle-hash",
        signals={"approvals": {"required": 1, "actual": 1}},
        risk_score=10.0,
        decision="ALLOW",
        reason_codes=["POLICY_ALLOWED"],
        timestamp="2026-02-13T12:00:00Z",
        engine_version="2.0.0",
        checkpoint_hashes=[],
    )
    return build_attestation_from_bundle(bundle)


def test_verify_attestation_endpoint_success():
    resp = client.post("/verify", json={"attestation": _sample_attestation()})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["schema_valid"] is True
    assert body["payload_hash_match"] is True
    assert body["trusted_issuer"] is True
    assert body["valid_signature"] is True


def test_verify_attestation_endpoint_accepts_raw_payload():
    resp = client.post("/verify", json=_sample_attestation())
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_public_keys_endpoint_is_public():
    resp = client.get("/keys")
    assert resp.status_code == 200
    body = resp.json()
    assert body["issuer"] == "releasegate"
    assert body["keys"]
