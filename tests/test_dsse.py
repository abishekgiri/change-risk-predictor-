from __future__ import annotations

from releasegate.attestation.crypto import current_key_id, load_private_key_from_env, load_public_keys_map
from releasegate.attestation.dsse import verify_dsse, wrap_dsse
from releasegate.attestation.intoto import (
    PREDICATE_TYPE_RELEASEGATE_V1,
    STATEMENT_TYPE_V1,
    build_intoto_statement,
)
from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_analysis_result


def _sample_attestation() -> dict:
    bundle = build_bundle_from_analysis_result(
        tenant_id="tenant-test",
        repo="org/service-api",
        pr_number=15,
        commit_sha="5f4dcc3b5aa765d61d8327deb882cf99",
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.85,
        decision="BLOCK",
        reason_codes=["POLICY_BLOCKED"],
        signals={"changed_files": 22},
        engine_version="2.0.0",
        timestamp="2026-02-13T00:00:00Z",
    )
    return build_attestation_from_bundle(bundle)


def test_intoto_statement_fields_correct():
    attestation = _sample_attestation()
    statement = build_intoto_statement(attestation)

    assert statement["_type"] == STATEMENT_TYPE_V1
    assert statement["predicateType"] == PREDICATE_TYPE_RELEASEGATE_V1
    assert statement["predicate"] == attestation
    assert statement["subject"][0]["name"] == attestation["subject"]["repo"]
    assert statement["subject"][0]["digest"]["sha256"] == attestation["subject"]["commit_sha"]


def test_dsse_roundtrip_verify_passes():
    attestation = _sample_attestation()
    statement = build_intoto_statement(attestation)

    envelope = wrap_dsse(
        statement,
        signing_key=load_private_key_from_env(),
        key_id=current_key_id(),
    )

    valid, decoded, error = verify_dsse(envelope, load_public_keys_map())
    assert valid is True
    assert error is None
    assert decoded == statement


def test_dsse_tamper_payload_fails():
    attestation = _sample_attestation()
    statement = build_intoto_statement(attestation)
    envelope = wrap_dsse(
        statement,
        signing_key=load_private_key_from_env(),
        key_id=current_key_id(),
    )

    tampered = dict(envelope)
    payload = str(tampered["payload"])
    tampered["payload"] = ("A" if payload[:1] != "A" else "B") + payload[1:]

    valid, decoded, error = verify_dsse(tampered, load_public_keys_map())
    assert valid is False
    assert decoded is None
    assert error == "SIGNATURE_INVALID"


def test_dsse_key_mismatch_fails():
    attestation = _sample_attestation()
    statement = build_intoto_statement(attestation)
    envelope = wrap_dsse(
        statement,
        signing_key=load_private_key_from_env(),
        key_id=current_key_id(),
    )

    mismatched = {
        **envelope,
        "signatures": [{
            **envelope["signatures"][0],
            "keyid": "unknown-key-id",
        }],
    }
    valid, decoded, error = verify_dsse(mismatched, load_public_keys_map())
    assert valid is False
    assert decoded is None
    assert error == "UNKNOWN_KEY_ID"
