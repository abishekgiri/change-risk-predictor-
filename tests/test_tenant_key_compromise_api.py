from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
import pytest

from releasegate.attestation.canonicalize import canonicalize_attestation_payload
from releasegate.attestation.crypto import sign_bytes
from releasegate.audit.attestations import record_release_attestation
from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _build_attestation(
    *,
    tenant_id: str,
    key_id: str,
    private_key_pem: str,
    decision_id: str,
) -> dict:
    issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = {
        "schema_version": "1.0.0",
        "attestation_type": "releasegate.release_attestation",
        "issued_at": issued_at,
        "policy_schema_version": "v1",
        "tenant_id": tenant_id,
        "decision_id": decision_id,
        "engine_version": "test-engine",
        "subject": {
            "repo": "demo/repo",
            "commit_sha": "abc123",
            "pr_number": 1,
        },
        "policy": {
            "policy_version": "1.0.0",
            "policy_hash": "policy-hash",
            "policy_bundle_hash": "bundle-hash",
            "policy_scope": ["pull_request"],
            "policy_resolution_hash": "policy-hash",
        },
        "decision": {
            "decision": "ALLOW",
            "risk_score": 0.1,
            "risk_level": "LOW",
            "reason_codes": ["POLICY_ALLOWED"],
        },
        "evidence": {
            "signals_summary": {"risk": "LOW"},
            "signal_hash": "sha256:" + ("0" * 64),
            "dependency_provenance": {},
            "override_flags": [],
            "checkpoint_hashes": [],
            "decision_bundle_hash": "sha256:" + ("1" * 64),
        },
        "issuer": {
            "org_id": tenant_id,
            "app_id": "releasegate",
            "environment": "test",
            "key_id": key_id,
        },
    }
    payload_hash = hashlib.sha256(canonicalize_attestation_payload(payload)).hexdigest()
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature = sign_bytes(private_key, payload_hash)
    return {
        **payload,
        "signature": {
            "algorithm": "ed25519",
            "signed_payload_hash": f"sha256:{payload_hash}",
            "signature_bytes": signature,
        },
    }


def test_emergency_rotate_compromise_report_and_verify_flags():
    _reset_db()
    tenant_id = "tenant-compromise-test"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin"])

    first = client.post(
        f"/tenants/{tenant_id}/rotate-key",
        json={},
        headers=headers,
    )
    assert first.status_code == 200

    second = client.post(
        f"/tenants/{tenant_id}/rotate-key",
        json={},
        headers=headers,
    )
    assert second.status_code == 200
    second_key = second.json()

    attestation = _build_attestation(
        tenant_id=tenant_id,
        key_id=second_key["key_id"],
        private_key_pem=str(second_key["private_key"]),
        decision_id="decision-compromised-1",
    )
    attestation_id = record_release_attestation(
        decision_id="decision-compromised-1",
        tenant_id=tenant_id,
        repo="demo/repo",
        pr_number=1,
        attestation=attestation,
    )
    assert attestation_id

    emergency = client.post(
        f"/tenants/{tenant_id}/emergency-rotate",
        json={"reason": "suspected compromise"},
        headers=headers,
    )
    assert emergency.status_code == 200
    emergency_body = emergency.json()
    assert emergency_body["revoked_key_id"] == second_key["key_id"]
    assert emergency_body["affected_count"] >= 1
    assert attestation_id in emergency_body["affected_attestation_ids"]

    verify_resp = client.post("/verify", json={"attestation": attestation})
    assert verify_resp.status_code == 200
    verify_body = verify_resp.json()
    assert verify_body["valid_signature"] is True
    assert verify_body["key_revoked"] is True
    assert verify_body["compromised"] is True
    assert verify_body["accepted"] is False

    report = client.get(
        f"/tenants/{tenant_id}/compromise-report",
        headers=jwt_headers(tenant_id=tenant_id, roles=["auditor"]),
    )
    assert report.status_code == 200
    report_body = report.json()
    assert report_body["total_events"] >= 1
    assert report_body["total_affected_attestations"] >= 1


def test_bulk_resign_and_key_access_log():
    _reset_db()
    tenant_id = "tenant-resign-test"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin"])

    first = client.post(f"/tenants/{tenant_id}/rotate-key", json={}, headers=headers)
    assert first.status_code == 200
    first_key = first.json()

    attestation = _build_attestation(
        tenant_id=tenant_id,
        key_id=first_key["key_id"],
        private_key_pem=str(first_key["private_key"]),
        decision_id="decision-compromised-2",
    )
    record_release_attestation(
        decision_id="decision-compromised-2",
        tenant_id=tenant_id,
        repo="demo/repo",
        pr_number=2,
        attestation=attestation,
    )

    emergency = client.post(
        f"/tenants/{tenant_id}/emergency-rotate",
        json={"reason": "rotate now"},
        headers=headers,
    )
    assert emergency.status_code == 200

    resign = client.post(
        f"/tenants/{tenant_id}/re-sign",
        json={"limit": 50},
        headers=headers,
    )
    assert resign.status_code == 200
    resign_body = resign.json()
    assert resign_body["resigned_count"] >= 1
    assert "supersedes_attestation_id" in resign_body["items"][0]

    verify_resp = client.post("/verify", json={"attestation": attestation})
    assert verify_resp.status_code == 200
    verify_body = verify_resp.json()
    assert verify_body["valid_signature"] is True
    assert verify_body["accepted"] is False
    assert verify_body["superseded_by_resignature"] is True
    assert verify_body["superseding_signature_valid"] is True
    assert verify_body["superseding_accepted"] is True
    assert verify_body["accepted_effective"] is True

    key_access = client.get(
        f"/tenants/{tenant_id}/key-access-log",
        headers=jwt_headers(tenant_id=tenant_id, roles=["admin"]),
    )
    assert key_access.status_code == 200
    key_access_body = key_access.json()
    assert key_access_body["count"] >= 1
    operations = {item.get("operation") for item in key_access_body["items"]}
    assert operations & {"decrypt", "sign"}


def test_emergency_rotate_is_idempotent_with_idempotency_key():
    _reset_db()
    tenant_id = "tenant-idem-test"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin"])
    idem_headers = {
        **headers,
        "Idempotency-Key": "idem-emergency-rotate-1",
    }

    created = client.post(f"/tenants/{tenant_id}/rotate-key", json={}, headers=headers)
    assert created.status_code == 200

    first = client.post(
        f"/tenants/{tenant_id}/emergency-rotate",
        json={"reason": "suspected compromise"},
        headers=idem_headers,
    )
    assert first.status_code == 200
    first_body = first.json()

    second = client.post(
        f"/tenants/{tenant_id}/emergency-rotate",
        json={"reason": "suspected compromise"},
        headers=idem_headers,
    )
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["event_id"] == first_body["event_id"]
    assert second_body["replacement_key_id"] == first_body["replacement_key_id"]


def test_emergency_rotate_error_is_idempotent_and_replayed_as_error():
    _reset_db()
    tenant_id = "tenant-idem-error-test"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin"])
    idem_headers = {
        **headers,
        "Idempotency-Key": "idem-emergency-rotate-error-1",
    }

    created = client.post(f"/tenants/{tenant_id}/rotate-key", json={}, headers=headers)
    assert created.status_code == 200

    payload = {
        "reason": "future window should fail",
        "compromise_start": "2999-01-01T00:00:00Z",
    }
    first = client.post(
        f"/tenants/{tenant_id}/emergency-rotate",
        json=payload,
        headers=idem_headers,
    )
    assert first.status_code == 400
    first_detail = str(first.json().get("detail") or "")
    assert "cannot be in the future" in first_detail

    second = client.post(
        f"/tenants/{tenant_id}/emergency-rotate",
        json=payload,
        headers=idem_headers,
    )
    assert second.status_code == 400
    second_detail = str(second.json().get("detail") or "")
    assert "cannot be in the future" in second_detail


def test_compromise_and_key_access_endpoints_are_tenant_scoped():
    _reset_db()
    tenant_a = "tenant-a-scope"
    tenant_b = "tenant-b-scope"
    admin_a = jwt_headers(tenant_id=tenant_a, roles=["admin"])
    admin_b = jwt_headers(tenant_id=tenant_b, roles=["admin"])

    created = client.post(f"/tenants/{tenant_a}/rotate-key", json={}, headers=admin_a)
    assert created.status_code == 200
    emergency = client.post(
        f"/tenants/{tenant_a}/emergency-rotate",
        json={"reason": "scope test"},
        headers={**admin_a, "Idempotency-Key": "scope-idem-1"},
    )
    assert emergency.status_code == 200

    denied_log = client.get(f"/tenants/{tenant_a}/key-access-log", headers=admin_b)
    assert denied_log.status_code == 403
    denied_report = client.get(f"/tenants/{tenant_a}/compromise-report", headers=admin_b)
    assert denied_report.status_code == 403


def test_key_access_log_is_append_only():
    _reset_db()
    tenant_id = "tenant-append-only"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin"])

    created = client.post(f"/tenants/{tenant_id}/rotate-key", json={}, headers=headers)
    assert created.status_code == 200
    log_resp = client.get(f"/tenants/{tenant_id}/key-access-log", headers=headers)
    assert log_resp.status_code == 200
    items = log_resp.json()["items"]
    assert items
    access_id = str(items[0]["access_id"])

    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        with pytest.raises(sqlite3.IntegrityError):
            cursor.execute(
                "UPDATE key_access_log SET actor = ? WHERE tenant_id = ? AND access_id = ?",
                ("tamper", tenant_id, access_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            cursor.execute(
                "DELETE FROM key_access_log WHERE tenant_id = ? AND access_id = ?",
                (tenant_id, access_id),
            )
    finally:
        conn.close()


def test_verify_fails_closed_when_compromise_check_errors(monkeypatch):
    _reset_db()
    tenant_id = "tenant-fail-closed-check"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin"])

    rotate = client.post(f"/tenants/{tenant_id}/rotate-key", json={}, headers=headers)
    assert rotate.status_code == 200
    key = rotate.json()
    attestation = _build_attestation(
        tenant_id=tenant_id,
        key_id=key["key_id"],
        private_key_pem=str(key["private_key"]),
        decision_id="decision-fail-closed-1",
    )

    def _raise_compromise_error(*, tenant_id: str, attestation_id: str):
        raise RuntimeError("transient datastore failure")

    monkeypatch.setattr(
        "releasegate.tenants.compromise.is_attestation_compromised",
        _raise_compromise_error,
    )

    verify_resp = client.post("/verify", json={"attestation": attestation})
    assert verify_resp.status_code == 503
    body = verify_resp.json()
    assert body.get("detail") == "Attestation compromise status check failed"
