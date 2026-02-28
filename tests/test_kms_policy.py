from __future__ import annotations

import pytest

from releasegate.attestation import crypto as attestation_crypto
from releasegate.attestation.crypto import MissingSigningKeyError
from releasegate.crypto.kms_client import ensure_kms_runtime_policy, get_kms_client
from releasegate.security.checkpoint_keys import _legacy_fernet as checkpoint_legacy_fernet


def test_strict_kms_blocks_local_mode(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_STRICT_KMS", "1")
    monkeypatch.setenv("RELEASEGATE_KMS_MODE", "local")
    get_kms_client.cache_clear()
    with pytest.raises(RuntimeError, match="RELEASEGATE_STRICT_KMS"):
        ensure_kms_runtime_policy()


def test_cloud_mode_requires_adapter(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_STRICT_KMS", "1")
    monkeypatch.setenv("RELEASEGATE_KMS_MODE", "aws")
    get_kms_client.cache_clear()
    with pytest.raises(RuntimeError, match="cloud adapter is not implemented"):
        get_kms_client()


def test_local_mode_allowed_when_not_strict(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_STRICT_KMS", "0")
    monkeypatch.setenv("RELEASEGATE_KMS_MODE", "local")
    monkeypatch.setenv("RELEASEGATE_LOCAL_KMS_WRAPPING_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    get_kms_client.cache_clear()
    client = get_kms_client()
    assert client is not None


def test_checkpoint_legacy_key_requires_secret_in_production(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ENV", "production")
    monkeypatch.delenv("RELEASEGATE_KEY_ENCRYPTION_SECRET", raising=False)
    with pytest.raises(ValueError, match="must be set in production"):
        checkpoint_legacy_fernet()


def test_load_private_key_for_tenant_rejects_kms_direct_without_local_key(monkeypatch):
    def _fake_record(*args, **kwargs):
        return {
            "tenant_id": "tenant-a",
            "key_id": "tenant-a-kms-direct",
            "private_key": None,
            "signing_mode": "kms_direct",
        }

    monkeypatch.setattr(
        "releasegate.tenants.keys.get_active_tenant_signing_key_record",
        _fake_record,
    )
    with pytest.raises(MissingSigningKeyError, match="Use sign_message_for_tenant"):
        attestation_crypto.load_private_key_for_tenant("tenant-a")


def test_sign_message_for_tenant_uses_kms_direct_signer(monkeypatch):
    captured = {"log_calls": []}

    class _FakeKMS:
        def sign(self, *, key_id: str, payload: bytes) -> bytes:
            assert key_id == "tenant-a-kms-direct"
            assert payload == b"payload-bytes"
            return b"kms-signature"

    def _fake_record(*args, **kwargs):
        return {
            "tenant_id": "tenant-a",
            "key_id": "tenant-a-kms-direct",
            "private_key": None,
            "signing_mode": "kms_direct",
            "encryption_mode": "kms_envelope_v1",
            "kms_key_id": "kms-arn",
        }

    def _fake_log_key_access(**kwargs):
        captured["log_calls"].append(kwargs)
        return "access-log-id"

    monkeypatch.setattr(
        "releasegate.tenants.keys.get_active_tenant_signing_key_record",
        _fake_record,
    )
    monkeypatch.setattr("releasegate.crypto.kms_client.get_kms_client", lambda: _FakeKMS())
    monkeypatch.setattr("releasegate.security.key_access.log_key_access", _fake_log_key_access)

    signature, key_id = attestation_crypto.sign_message_for_tenant("tenant-a", b"payload-bytes")
    assert signature == b"kms-signature"
    assert key_id == "tenant-a-kms-direct"
    assert captured["log_calls"]
    assert captured["log_calls"][0]["operation"] == "sign"
