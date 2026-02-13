from __future__ import annotations

import pytest

from releasegate.attestation.crypto import MissingSigningKeyError, load_public_keys_map
from releasegate.attestation.service import build_attestation_from_bundle
from releasegate.attestation.types import DecisionBundle
from releasegate.attestation.verify import verify_attestation_payload


def _bundle() -> DecisionBundle:
    return DecisionBundle(
        tenant_id="tenant-test",
        decision_id="decision-attest-001",
        repo="org/service-api",
        pr_number=184,
        commit_sha="abc123def456",
        merge_sha="def456abc123",
        policy_version="1.0.0",
        policy_hash="policy-hash-demo",
        policy_bundle_hash="bundle-hash-demo",
        signals={"approvals": {"required": 2, "actual": 1}},
        risk_score=0.72,
        decision="BLOCK",
        reason_codes=["POLICY_BLOCKED"],
        timestamp="2026-02-13T12:00:00Z",
        engine_version="2.0.0",
        checkpoint_hashes=["checkpoint-a", "checkpoint-b"],
    )


def _public_keys() -> dict[str, str]:
    return load_public_keys_map()


def test_release_attestation_sign_and_verify_round_trip():
    attestation = build_attestation_from_bundle(_bundle())
    report = verify_attestation_payload(attestation, public_keys_by_key_id=_public_keys())
    assert report["schema_valid"] is True
    assert report["payload_hash_match"] is True
    assert report["trusted_issuer"] is True
    assert report["valid_signature"] is True
    assert report["errors"] == []


def test_release_attestation_fails_when_payload_tampered():
    attestation = build_attestation_from_bundle(_bundle())
    attestation["decision"]["decision"] = "ALLOW"
    report = verify_attestation_payload(attestation, public_keys_by_key_id=_public_keys())
    assert report["schema_valid"] is True
    assert report["payload_hash_match"] is False
    assert report["valid_signature"] is False
    assert "PAYLOAD_HASH_MISMATCH" in report["errors"]


def test_release_attestation_fails_when_risk_score_changes():
    attestation = build_attestation_from_bundle(_bundle())
    attestation["decision"]["risk_score"] = 0.73
    report = verify_attestation_payload(attestation, public_keys_by_key_id=_public_keys())
    assert report["payload_hash_match"] is False
    assert report["valid_signature"] is False


def test_release_attestation_fails_for_unknown_key_id():
    attestation = build_attestation_from_bundle(_bundle())
    attestation["issuer"]["key_id"] = "unknown-key-id"
    report = verify_attestation_payload(attestation, public_keys_by_key_id=_public_keys())
    assert report["schema_valid"] is True
    assert report["trusted_issuer"] is False
    assert report["valid_signature"] is False
    assert "UNKNOWN_KEY_ID" in report["errors"]


def test_release_attestation_rejects_extra_fields():
    attestation = build_attestation_from_bundle(_bundle())
    attestation["unexpected"] = True
    report = verify_attestation_payload(attestation, public_keys_by_key_id=_public_keys())
    assert report["schema_valid"] is False
    assert report["valid_signature"] is False
    assert report["payload_hash_match"] is False


def test_release_attestation_hash_unchanged_when_dict_keys_reordered():
    base = _bundle().model_dump(mode="json")
    variant = dict(base)
    variant["signals"] = {"z_last": 1, "a_first": {"y": 2, "x": 1}}
    base["signals"] = {"a_first": {"x": 1, "y": 2}, "z_last": 1}

    att_a = build_attestation_from_bundle(base)
    att_b = build_attestation_from_bundle(variant)
    assert att_a["signature"]["signed_payload_hash"] == att_b["signature"]["signed_payload_hash"]
    assert att_a["signature"]["signature_bytes"] == att_b["signature"]["signature_bytes"]


def test_release_attestation_requires_configured_signing_key(monkeypatch):
    monkeypatch.delenv("RELEASEGATE_SIGNING_KEY", raising=False)
    with pytest.raises(MissingSigningKeyError):
        build_attestation_from_bundle(_bundle())


def test_release_attestation_verify_requires_explicit_key_map():
    attestation = build_attestation_from_bundle(_bundle())
    with pytest.raises(TypeError):
        verify_attestation_payload(attestation)  # type: ignore[call-arg]
