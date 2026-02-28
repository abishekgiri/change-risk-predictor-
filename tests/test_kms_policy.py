from __future__ import annotations

import pytest

from releasegate.crypto import kms_client
from releasegate.security.checkpoint_keys import _legacy_fernet as checkpoint_legacy_fernet


def test_strict_kms_blocks_local_mode(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_STRICT_KMS", "1")
    monkeypatch.setenv("RELEASEGATE_KMS_MODE", "local")
    kms_client.get_kms_client.cache_clear()
    with pytest.raises(RuntimeError, match="RELEASEGATE_STRICT_KMS"):
        kms_client.ensure_kms_runtime_policy()


def test_gcp_cloud_mode_requires_adapter(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_STRICT_KMS", "1")
    monkeypatch.setenv("RELEASEGATE_KMS_MODE", "gcp")
    kms_client.get_kms_client.cache_clear()
    with pytest.raises(RuntimeError, match="cloud adapter is not implemented"):
        kms_client.get_kms_client()


def test_aws_mode_requires_boto3(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_STRICT_KMS", "1")
    monkeypatch.setenv("RELEASEGATE_KMS_MODE", "aws")
    monkeypatch.setenv("RELEASEGATE_KMS_KEY_ID", "arn:aws:kms:us-east-1:111122223333:key/demo")
    monkeypatch.setattr(kms_client, "_module_available", lambda name: False)
    kms_client.get_kms_client.cache_clear()
    with pytest.raises(RuntimeError, match="requires boto3"):
        kms_client.get_kms_client()


def test_aws_mode_requires_default_key_id(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_STRICT_KMS", "1")
    monkeypatch.setenv("RELEASEGATE_KMS_MODE", "aws")
    monkeypatch.delenv("RELEASEGATE_KMS_KEY_ID", raising=False)
    monkeypatch.setattr(kms_client, "_module_available", lambda name: True)
    kms_client.get_kms_client.cache_clear()
    with pytest.raises(RuntimeError, match="RELEASEGATE_KMS_KEY_ID"):
        kms_client.get_kms_client()


def test_local_mode_allowed_when_not_strict(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_STRICT_KMS", "0")
    monkeypatch.setenv("RELEASEGATE_KMS_MODE", "local")
    monkeypatch.setenv("RELEASEGATE_LOCAL_KMS_WRAPPING_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    kms_client.get_kms_client.cache_clear()
    client = kms_client.get_kms_client()
    assert client is not None


def test_checkpoint_legacy_key_requires_secret_in_production(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ENV", "production")
    monkeypatch.delenv("RELEASEGATE_KEY_ENCRYPTION_SECRET", raising=False)
    with pytest.raises(ValueError, match="must be set in production"):
        checkpoint_legacy_fernet()
