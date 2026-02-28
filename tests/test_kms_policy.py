from __future__ import annotations

import pytest

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
