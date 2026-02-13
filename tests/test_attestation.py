import os
from fastapi.testclient import TestClient
from releasegate.attestation.service import build_attestation_from_bundle
from releasegate.attestation.types import DecisionBundle
from releasegate.attestation.engine import AttestationEngine
from releasegate.attestation.key_manager import AttestationKeyManager
from releasegate.server import app

client = TestClient(app)

def test_key_manager_generates_keys():
    # Ensure we get a valid key pair even without env var
    if "RELEASEGATE_ATTESTATION_KEY" in os.environ:
        del os.environ["RELEASEGATE_ATTESTATION_KEY"]
        
    private_key, key_id = AttestationKeyManager.load_signing_key()
    assert private_key
    assert key_id

    public_pem = AttestationKeyManager.get_public_key_pem(private_key)
    assert b"BEGIN PUBLIC KEY" in public_pem

def test_engine_roundtrip():
    private_key, key_id = AttestationKeyManager.load_signing_key()
    public_pem = AttestationKeyManager.get_public_key_pem(private_key)
    
    decision = {
        "release_status": "ALLOWED",
        "decision_id": "test-decision-123",
        "repo": "org/repo",
        "pr_number": 123,
        "head_sha": "abc1234",
        "policy_hash": "poly-hash",
        "decision_hash": "dec-hash",
    }
    
    # Sign
    attestation = AttestationEngine.create_attestation(
        tenant_id="default",
        decision=decision,
        private_key=private_key,
        key_id=key_id
    )
    
    assert attestation["attestation_id"]
    assert attestation["signature"]["value"]
    
    # Verify
    valid = AttestationEngine.verify_attestation(attestation, public_pem)
    assert valid

def test_engine_rejects_tampered_payload():
    private_key, key_id = AttestationKeyManager.load_signing_key()
    public_pem = AttestationKeyManager.get_public_key_pem(private_key)
    
    decision = {
        "release_status": "ALLOWED",
        "decision_id": "test",
        "decision_hash": "hash"
    }
    attestation = AttestationEngine.create_attestation("t1", decision, private_key, key_id)
    
    # Tamper
    attestation["assertion"]["release_status"] = "BLOCKED"
    
    valid = AttestationEngine.verify_attestation(attestation, public_pem)
    assert not valid

def test_api_keys_endpoint():
    resp = client.get("/keys")
    assert resp.status_code == 200
    data = resp.json()
    assert data["issuer"] == "releasegate"
    assert "keys" in data
    assert len(data["keys"]) > 0
    key = data["keys"][0]
    assert key["kty"] == "OKP"
    assert "pem" in key

def test_api_verify_endpoint():
    att = build_attestation_from_bundle(
        DecisionBundle(
            tenant_id="default",
            decision_id="api-test",
            repo="org/repo",
            pr_number=1,
            commit_sha="abc123",
            policy_version="1.0.0",
            policy_hash="policy-hash",
            policy_bundle_hash="bundle-hash",
            signals={"approvals": {"required": 1, "actual": 1}},
            risk_score=0.2,
            decision="ALLOW",
            reason_codes=["POLICY_ALLOWED"],
            timestamp="2026-02-13T00:00:00Z",
            engine_version="2.0.0",
            checkpoint_hashes=[],
        )
    )

    resp = client.post("/verify", json={"attestation": att})
    assert resp.status_code == 200
    res = resp.json()
    assert res["ok"] is True
    assert res["valid_signature"] is True

def test_api_verify_rejects_bad_sig():
    att = build_attestation_from_bundle(
        DecisionBundle(
            tenant_id="default",
            decision_id="api-bad",
            repo="org/repo",
            pr_number=1,
            commit_sha="abc123",
            policy_version="1.0.0",
            policy_hash="policy-hash",
            policy_bundle_hash="bundle-hash",
            signals={},
            risk_score=0.2,
            decision="ALLOW",
            reason_codes=["POLICY_ALLOWED"],
            timestamp="2026-02-13T00:00:00Z",
            engine_version="2.0.0",
            checkpoint_hashes=[],
        )
    )
    att["signature"]["signature_bytes"] = "bad"

    resp = client.post("/verify", json={"attestation": att})
    assert resp.status_code == 200
    assert resp.json()["ok"] is False
