from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives import serialization

from releasegate.attestation.dsse import wrap_dsse
from releasegate.attestation.intoto import build_proof_pack_statement
from releasegate.audit.proof_pack_verify import (
    VerificationFailure,
    _verify_supply_chain_envelope,
)
from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db
from releasegate.tenants.keys import revoke_tenant_signing_key, rotate_tenant_signing_key
from releasegate.utils.canonical import sha256_json


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def _build_signed_bundle(*, tenant_id: str, decision_id: str, key_id: str, private_key_pem: str) -> dict:
    base_bundle = {
        "schema_name": "proof_pack",
        "schema_version": "proof_pack_v1",
        "bundle_version": "audit_proof_v1",
        "tenant_id": tenant_id,
        "ids": {"decision_id": decision_id},
        "decision_id": decision_id,
        "integrity": {},
        "evidence_graph": {},
    }
    export_checksum = sha256_json(base_bundle)
    statement = build_proof_pack_statement(base_bundle, export_checksum=export_checksum)
    signing_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    envelope = wrap_dsse(statement, signing_key=signing_key, key_id=key_id)
    return {
        **base_bundle,
        "in_toto_statement": statement,
        "dsse_envelope": envelope,
    }


def test_proof_pack_verify_accepts_revoked_key_in_grace_mode(clean_db, monkeypatch):
    first = rotate_tenant_signing_key(tenant_id="tenant-test", created_by="alice")
    first_key_id = str(first["key_id"])
    first_private_key = str(first["private_key"])
    rotate_tenant_signing_key(tenant_id="tenant-test", created_by="bob")
    revoke_tenant_signing_key(
        tenant_id="tenant-test",
        key_id=first_key_id,
        revoked_by="security-bot",
        reason="simulated compromise",
    )

    bundle = _build_signed_bundle(
        tenant_id="tenant-test",
        decision_id="decision-revoked-grace",
        key_id=first_key_id,
        private_key_pem=first_private_key,
    )
    monkeypatch.setenv("RELEASEGATE_ALLOW_REVOKED_SIGNING_KEY_VERIFY", "true")
    report = _verify_supply_chain_envelope(bundle)
    assert report["ok"] is True
    assert first_key_id in report["revoked_signing_key_ids"]


def test_proof_pack_verify_rejects_revoked_key_in_strict_mode(clean_db, monkeypatch):
    first = rotate_tenant_signing_key(tenant_id="tenant-test", created_by="alice")
    first_key_id = str(first["key_id"])
    first_private_key = str(first["private_key"])
    rotate_tenant_signing_key(tenant_id="tenant-test", created_by="bob")
    revoke_tenant_signing_key(
        tenant_id="tenant-test",
        key_id=first_key_id,
        revoked_by="security-bot",
        reason="simulated compromise",
    )

    bundle = _build_signed_bundle(
        tenant_id="tenant-test",
        decision_id="decision-revoked-strict",
        key_id=first_key_id,
        private_key_pem=first_private_key,
    )
    monkeypatch.setenv("RELEASEGATE_ALLOW_REVOKED_SIGNING_KEY_VERIFY", "false")
    with pytest.raises(VerificationFailure) as exc:
        _verify_supply_chain_envelope(bundle)
    assert exc.value.code == "DSSE_SIGNING_KEY_REVOKED"
