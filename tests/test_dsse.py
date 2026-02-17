from __future__ import annotations

import base64
import os

import pytest
from fastapi.testclient import TestClient

from releasegate.attestation.crypto import current_key_id, load_private_key_from_env, load_public_keys_map
from releasegate.attestation.dsse import DSSE_PAYLOAD_TYPE, verify_dsse, wrap_dsse
from releasegate.attestation.intoto import (
    PREDICATE_TYPE_RELEASEGATE_V1,
    STATEMENT_TYPE_V1,
    build_intoto_statement,
)
from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_analysis_result
from releasegate.audit.attestations import record_release_attestation
from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db


client = TestClient(app)


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


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
    assert statement["subject"][0]["name"] == (
        f"git+https://github.com/{attestation['subject']['repo']}@{attestation['subject']['commit_sha']}"
    )
    signed_payload_hash = attestation["signature"]["signed_payload_hash"]
    digest = signed_payload_hash.split(":", 1)[1] if ":" in signed_payload_hash else signed_payload_hash
    assert statement["subject"][0]["digest"]["sha256"] == digest.lower()


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


def test_dsse_conformance_invariants_and_determinism():
    attestation = _sample_attestation()
    statement = build_intoto_statement(attestation)
    signing_key = load_private_key_from_env()
    key_id = current_key_id()

    env1 = wrap_dsse(statement, signing_key=signing_key, key_id=key_id)
    env2 = wrap_dsse(statement, signing_key=signing_key, key_id=key_id)

    assert env1 == env2
    assert env1["payloadType"] == DSSE_PAYLOAD_TYPE
    assert env1["signatures"][0]["keyid"] == key_id

    payload_bytes = base64.b64decode(env1["payload"].encode("ascii"), validate=True)
    assert payload_bytes.startswith(b"{")

    sig_bytes = base64.b64decode(env1["signatures"][0]["sig"].encode("ascii"), validate=True)
    assert len(sig_bytes) == 64

    valid, decoded, error = verify_dsse(env1, load_public_keys_map())
    assert valid is True
    assert error is None
    assert decoded["_type"] == STATEMENT_TYPE_V1
    assert decoded["predicateType"] == PREDICATE_TYPE_RELEASEGATE_V1
    assert isinstance(decoded.get("subject"), list) and len(decoded["subject"]) >= 1

    predicate = decoded["predicate"]
    signed_payload_hash = str(predicate["signature"]["signed_payload_hash"])
    digest = signed_payload_hash.split(":", 1)[1] if ":" in signed_payload_hash else signed_payload_hash
    assert decoded["subject"][0]["digest"]["sha256"] == digest.lower()


def test_dsse_signature_length_invalid_is_rejected():
    attestation = _sample_attestation()
    statement = build_intoto_statement(attestation)
    envelope = wrap_dsse(
        statement,
        signing_key=load_private_key_from_env(),
        key_id=current_key_id(),
    )
    envelope["signatures"][0]["sig"] = base64.b64encode(b"abc").decode("ascii")

    valid, decoded, error = verify_dsse(envelope, load_public_keys_map())
    assert valid is False
    assert decoded is None
    assert error == "SIGNATURE_LEN_INVALID"


def test_dsse_export_endpoint_returns_signed_envelope(clean_db):
    attestation = _sample_attestation()
    attestation_id = record_release_attestation(
        decision_id=str(attestation["decision_id"]),
        tenant_id="tenant-test",
        repo=str(attestation["subject"]["repo"]),
        pr_number=attestation["subject"].get("pr_number"),
        attestation=attestation,
    )

    resp = client.get(f"/attestations/{attestation_id}.dsse", params={"tenant_id": "tenant-test"})
    assert resp.status_code == 200
    envelope = resp.json()
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert envelope["signatures"]

    valid, decoded, error = verify_dsse(envelope, load_public_keys_map())
    assert valid is True
    assert error is None
    assert decoded["_type"] == STATEMENT_TYPE_V1
    assert decoded["predicateType"] == PREDICATE_TYPE_RELEASEGATE_V1
    assert decoded["predicate"]["decision_id"] == attestation["decision_id"]


def test_dsse_export_endpoint_404_when_missing(clean_db):
    resp = client.get("/attestations/does-not-exist.dsse", params={"tenant_id": "tenant-test"})
    assert resp.status_code == 404
