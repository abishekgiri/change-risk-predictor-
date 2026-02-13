from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from releasegate.attestation.crypto import (
    current_key_id,
    load_root_private_key_from_env,
    public_key_pem_from_private,
)
from releasegate.attestation.key_manifest import (
    build_key_manifest,
    key_status_from_manifest,
    reset_manifest_cache,
    sign_key_manifest,
    verify_key_manifest,
)
from releasegate.attestation.sdk import verify_with_manifest
from releasegate.attestation.service import build_attestation_from_bundle
from releasegate.attestation.types import DecisionBundle
from releasegate.server import app


def _public_pem_from_seed(hex_seed: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_seed))
    return public_key_pem_from_private(private_key)


def _sample_bundle() -> DecisionBundle:
    return DecisionBundle(
        tenant_id="tenant-test",
        decision_id="decision-manifest-001",
        repo="org/service-api",
        pr_number=15,
        commit_sha="abc123",
        policy_version="1.0.0",
        policy_hash="policy-hash",
        policy_bundle_hash="policy-bundle-hash",
        signals={"approvals": {"required": 1, "actual": 1}},
        risk_score=0.2,
        decision="ALLOW",
        reason_codes=["POLICY_ALLOWED"],
        timestamp="2026-02-13T03:00:00Z",
        engine_version="2.0.0",
        checkpoint_hashes=[],
    )


def test_manifest_signature_round_trip(monkeypatch):
    key_map = {
        "rg-prod-2026-01": _public_pem_from_seed("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9d1f1a2d46a1b8f12"),
        "rg-prod-2026-02": _public_pem_from_seed("3e2c4be3b55a8d8f0d57d813f8de6c0fa0f7dd8e3f5334f6767550f337f4d2a1"),
    }
    monkeypatch.setenv("RELEASEGATE_ATTESTATION_PUBLIC_KEYS", json.dumps(key_map))
    monkeypatch.setenv(
        "RELEASEGATE_ATTESTATION_KEY_METADATA",
        json.dumps(
            {
                "rg-prod-2026-01": {"created_at": "2026-02-01T00:00:00Z", "status": "ACTIVE"},
                "rg-prod-2026-02": {"created_at": "2026-02-10T00:00:00Z", "status": "DEPRECATED"},
            }
        ),
    )
    monkeypatch.setenv("RELEASEGATE_ROOT_KEY_ID", "rg-root-test-2026-01")
    monkeypatch.setenv(
        "RELEASEGATE_ROOT_SIGNING_KEY",
        "2b6f7db4a8d693f2e1e8e5c205f263f5bde1430f915f9fcb48b21f35bc95d5f3",
    )
    reset_manifest_cache()

    manifest = build_key_manifest(issued_at="2026-02-13T03:00:00Z")
    signature = sign_key_manifest(manifest)
    root_public = public_key_pem_from_private(load_root_private_key_from_env())
    report = verify_key_manifest(
        manifest,
        signature,
        trusted_root_public_keys_by_id={"rg-root-test-2026-01": root_public},
    )

    assert report["ok"] is True
    assert report["errors"] == []


def test_manifest_signature_fails_when_manifest_tampered(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ROOT_KEY_ID", "rg-root-test-2026-01")
    monkeypatch.setenv(
        "RELEASEGATE_ROOT_SIGNING_KEY",
        "2b6f7db4a8d693f2e1e8e5c205f263f5bde1430f915f9fcb48b21f35bc95d5f3",
    )
    reset_manifest_cache()
    manifest = build_key_manifest(issued_at="2026-02-13T03:00:00Z")
    signature = sign_key_manifest(manifest)
    manifest["keys"][0]["status"] = "REVOKED"

    root_public = public_key_pem_from_private(load_root_private_key_from_env())
    report = verify_key_manifest(
        manifest,
        signature,
        trusted_root_public_keys_by_id={"rg-root-test-2026-01": root_public},
    )

    assert report["ok"] is False
    assert "MANIFEST_HASH_MISMATCH" in report["errors"]


def test_well_known_manifest_endpoints(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ROOT_KEY_ID", "rg-root-test-2026-01")
    monkeypatch.setenv(
        "RELEASEGATE_ROOT_SIGNING_KEY",
        "2b6f7db4a8d693f2e1e8e5c205f263f5bde1430f915f9fcb48b21f35bc95d5f3",
    )
    reset_manifest_cache()
    client = TestClient(app)

    manifest_resp = client.get("/.well-known/releasegate-keys.json")
    sig_resp = client.get("/.well-known/releasegate-keys.sig")
    assert manifest_resp.status_code == 200
    assert sig_resp.status_code == 200

    manifest = manifest_resp.json()
    signature = sig_resp.json()
    assert manifest["manifest_version"] == "1"
    assert "manifest_hash" in manifest
    assert signature["manifest_hash"] == manifest["manifest_hash"]

    root_public = public_key_pem_from_private(load_root_private_key_from_env())
    report = verify_key_manifest(
        manifest,
        signature,
        trusted_root_public_keys_by_id={"rg-root-test-2026-01": root_public},
    )
    assert report["ok"] is True


def test_verify_with_manifest_marks_revoked_key_untrusted(monkeypatch):
    key_id = current_key_id()
    monkeypatch.setenv(
        "RELEASEGATE_ATTESTATION_KEY_METADATA",
        json.dumps(
            {
                key_id: {
                    "status": "REVOKED",
                    "created_at": "2026-02-01T00:00:00Z",
                    "revoked_at": "2026-02-12T00:00:00Z",
                    "revoked_reason": "compromised",
                }
            }
        ),
    )
    monkeypatch.setenv("RELEASEGATE_ROOT_KEY_ID", "rg-root-test-2026-01")
    monkeypatch.setenv(
        "RELEASEGATE_ROOT_SIGNING_KEY",
        "2b6f7db4a8d693f2e1e8e5c205f263f5bde1430f915f9fcb48b21f35bc95d5f3",
    )
    reset_manifest_cache()

    attestation = build_attestation_from_bundle(_sample_bundle())
    manifest = build_key_manifest(issued_at="2026-02-13T03:00:00Z")
    signature = sign_key_manifest(manifest)
    status = key_status_from_manifest(manifest, key_id)
    assert status["status"] == "REVOKED"

    root_public = public_key_pem_from_private(load_root_private_key_from_env())
    report = verify_with_manifest(
        attestation,
        manifest=manifest,
        signature_envelope=signature,
        trusted_root_public_keys_by_id={"rg-root-test-2026-01": root_public},
    )
    assert report["valid_signature"] is True
    assert report["trusted_issuer"] is False
    assert any(str(err).startswith("KEY_REVOKED:") for err in report["errors"])
