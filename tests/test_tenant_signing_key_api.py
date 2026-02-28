from __future__ import annotations

import os

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def test_tenant_signing_key_rotate_list_revoke_flow():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-test", roles=["admin"])

    first = client.post(
        "/tenants/tenant-test/rotate-key",
        json={"metadata": {"source": "test-suite"}},
        headers=headers,
    )
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["tenant_id"] == "tenant-test"
    assert first_body["status"] == "ACTIVE"
    assert first_body.get("private_key")

    second = client.post(
        "/tenants/tenant-test/rotate-key",
        json={},
        headers=headers,
    )
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["status"] == "ACTIVE"
    assert second_body["key_id"] != first_body["key_id"]

    listed = client.get(
        "/tenants/tenant-test/signing-keys",
        headers=jwt_headers(tenant_id="tenant-test", roles=["admin"]),
    )
    assert listed.status_code == 200
    rows = listed.json()["keys"]
    by_id = {row["key_id"]: row for row in rows}
    assert by_id[first_body["key_id"]]["status"] == "VERIFY_ONLY"
    assert by_id[second_body["key_id"]]["status"] == "ACTIVE"

    revoked = client.post(
        f"/tenants/tenant-test/signing-keys/{first_body['key_id']}/revoke",
        json={"reason": "routine test revocation"},
        headers=jwt_headers(tenant_id="tenant-test", roles=["admin"]),
    )
    assert revoked.status_code == 200
    revoked_body = revoked.json()
    assert revoked_body["status"] == "REVOKED"
    assert revoked_body["metadata"]["revocation_reason"] == "routine test revocation"

    keys_resp = client.get("/keys", params={"tenant_id": "tenant-test"})
    assert keys_resp.status_code == 200
    keys_by_id = {item["key_id"]: item for item in keys_resp.json()["keys"]}
    assert first_body["key_id"] not in keys_by_id
    assert second_body["key_id"] in keys_by_id


def test_tenant_signing_key_revoke_active_is_rejected():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-test", roles=["admin"])

    first = client.post(
        "/tenants/tenant-test/rotate-key",
        json={},
        headers=headers,
    )
    assert first.status_code == 200
    key_id = first.json()["key_id"]

    revoke_active = client.post(
        f"/tenants/tenant-test/signing-keys/{key_id}/revoke",
        json={},
        headers=headers,
    )
    assert revoke_active.status_code == 400
    assert "cannot revoke active signing key" in str(revoke_active.json().get("detail") or "")
