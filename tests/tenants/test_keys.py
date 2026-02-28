from __future__ import annotations

import os

import pytest

from releasegate.attestation.crypto import load_private_key_for_tenant, load_public_keys_map, public_key_pem_from_private
from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db
from releasegate.tenants.keys import (
    KEY_STATUS_ACTIVE,
    KEY_STATUS_REVOKED,
    KEY_STATUS_VERIFY_ONLY,
    get_tenant_signing_key_record,
    list_tenant_signing_keys,
    revoke_tenant_signing_key,
    rotate_tenant_signing_key,
)


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def test_tenant_signing_key_rotation_lifecycle(clean_db):
    first = rotate_tenant_signing_key(tenant_id="tenant-a", created_by="alice")
    second = rotate_tenant_signing_key(tenant_id="tenant-a", created_by="bob")

    assert str(first.get("status")) == KEY_STATUS_ACTIVE
    assert str(second.get("status")) == KEY_STATUS_ACTIVE
    assert str(first.get("key_id")) != str(second.get("key_id"))

    rows = list_tenant_signing_keys("tenant-a")
    by_id = {str(item.get("key_id")): item for item in rows}
    assert by_id[str(second.get("key_id"))]["status"] == KEY_STATUS_ACTIVE
    assert by_id[str(first.get("key_id"))]["status"] == KEY_STATUS_VERIFY_ONLY

    revoked = revoke_tenant_signing_key(
        tenant_id="tenant-a",
        key_id=str(first.get("key_id")),
        revoked_by="security-bot",
        reason="key compromise simulation",
    )
    assert revoked["status"] == KEY_STATUS_REVOKED
    assert revoked.get("revoked_at")

    refreshed = get_tenant_signing_key_record("tenant-a", str(first.get("key_id")))
    assert refreshed is not None
    assert refreshed["status"] == KEY_STATUS_REVOKED
    assert refreshed.get("metadata", {}).get("revocation_reason") == "key compromise simulation"


def test_tenant_signing_key_active_revocation_is_rejected(clean_db):
    active = rotate_tenant_signing_key(tenant_id="tenant-a", created_by="alice")
    with pytest.raises(ValueError, match="cannot revoke active signing key"):
        revoke_tenant_signing_key(
            tenant_id="tenant-a",
            key_id=str(active.get("key_id")),
            revoked_by="security-bot",
        )


def test_tenant_signing_key_crypto_resolution(clean_db):
    first = rotate_tenant_signing_key(tenant_id="tenant-a", created_by="alice")
    second = rotate_tenant_signing_key(tenant_id="tenant-a", created_by="bob")
    revoke_tenant_signing_key(
        tenant_id="tenant-a",
        key_id=str(first.get("key_id")),
        revoked_by="security-bot",
    )

    signing_key, key_id = load_private_key_for_tenant("tenant-a")
    assert key_id == str(second.get("key_id"))
    assert public_key_pem_from_private(signing_key).strip().startswith("-----BEGIN PUBLIC KEY-----")

    default_keys = load_public_keys_map(tenant_id="tenant-a")
    assert str(second.get("key_id")) in default_keys
    assert str(first.get("key_id")) not in default_keys

    all_keys = load_public_keys_map(tenant_id="tenant-a", include_revoked=True)
    assert str(second.get("key_id")) in all_keys
    assert str(first.get("key_id")) in all_keys
