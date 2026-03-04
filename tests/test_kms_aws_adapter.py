from __future__ import annotations

import os

import pytest

from releasegate.crypto.kms.aws_kms import AwsKMSClient


class _FakeAWSKMS:
    def __init__(self) -> None:
        self.last_generate = {}
        self.last_decrypt = {}
        self.last_sign = {}

    def generate_data_key(self, **kwargs):
        self.last_generate = dict(kwargs)
        plaintext = b"\x01" * 32
        return {
            "Plaintext": plaintext,
            "CiphertextBlob": b"wrapped:" + plaintext,
        }

    def decrypt(self, **kwargs):
        self.last_decrypt = dict(kwargs)
        blob = bytes(kwargs.get("CiphertextBlob") or b"")
        if not blob.startswith(b"wrapped:"):
            raise ValueError("invalid wrapped payload")
        return {
            "Plaintext": blob[len(b"wrapped:"):],
        }

    def sign(self, **kwargs):
        self.last_sign = dict(kwargs)
        message = bytes(kwargs.get("Message") or b"")
        return {"Signature": b"sig:" + message}


def test_aws_adapter_generate_and_decrypt_round_trip():
    fake = _FakeAWSKMS()
    context = {
        "tenant_id": "tenant-a",
        "key_id": "key-1",
        "table": "tenant_signing_keys",
    }
    client = AwsKMSClient(
        default_kms_key_id="arn:aws:kms:us-east-1:111122223333:key/default",
        client=fake,
    )
    plaintext, encrypted_data_key = client.generate_data_key(context=context)
    assert len(plaintext) == 32
    decrypted = client.decrypt_data_key(encrypted_data_key, context=context)
    assert decrypted == plaintext
    assert fake.last_generate["KeyId"] == "arn:aws:kms:us-east-1:111122223333:key/default"
    assert fake.last_decrypt["KeyId"] == "arn:aws:kms:us-east-1:111122223333:key/default"
    assert fake.last_generate["EncryptionContext"]["tenant_id"] == "tenant-a"
    assert fake.last_decrypt["EncryptionContext"]["table"] == "tenant_signing_keys"


def test_aws_adapter_detects_key_mismatch():
    fake = _FakeAWSKMS()
    client = AwsKMSClient(
        default_kms_key_id="arn:aws:kms:us-east-1:111122223333:key/default",
        client=fake,
    )
    plaintext, encrypted_data_key = client.generate_data_key()
    assert len(plaintext) == 32
    with pytest.raises(ValueError, match="KMS key mismatch"):
        client.decrypt_data_key(
            encrypted_data_key,
            kms_key_id="arn:aws:kms:us-east-1:111122223333:key/other",
        )


def test_aws_adapter_sign_uses_key_mapping(monkeypatch):
    fake = _FakeAWSKMS()
    client = AwsKMSClient(
        default_kms_key_id="arn:aws:kms:us-east-1:111122223333:key/default",
        client=fake,
    )
    monkeypatch.setenv(
        "RELEASEGATE_AWS_KMS_SIGNING_KEYS",
        '{"tenant-signing-key":"arn:aws:kms:us-east-1:111122223333:key/signing"}',
    )
    monkeypatch.delenv("RELEASEGATE_AWS_KMS_SIGNING_ALGORITHM", raising=False)
    signature = client.sign(key_id="tenant-signing-key", payload=b"hello")
    assert signature == b"sig:hello"
    assert fake.last_sign["KeyId"] == "arn:aws:kms:us-east-1:111122223333:key/signing"
    assert fake.last_sign["MessageType"] == "RAW"
    assert fake.last_sign["SigningAlgorithm"] == "EDDSA"


def test_aws_adapter_sign_mapping_requires_json_object(monkeypatch):
    fake = _FakeAWSKMS()
    client = AwsKMSClient(
        default_kms_key_id="arn:aws:kms:us-east-1:111122223333:key/default",
        client=fake,
    )
    monkeypatch.setenv("RELEASEGATE_AWS_KMS_SIGNING_KEYS", "[]")
    with pytest.raises(ValueError, match="JSON object"):
        client.sign(key_id="tenant-signing-key", payload=b"hello")


@pytest.mark.skipif(
    str(os.getenv("RELEASEGATE_RUN_AWS_KMS_CONTRACT_TESTS") or "").strip().lower() not in {"1", "true", "yes"},
    reason="set RELEASEGATE_RUN_AWS_KMS_CONTRACT_TESTS=1 to run live AWS KMS contract test",
)
def test_aws_adapter_contract_generate_and_decrypt():
    key_id = str(os.getenv("RELEASEGATE_AWS_KMS_CONTRACT_KEY_ID") or os.getenv("RELEASEGATE_KMS_KEY_ID") or "").strip()
    if not key_id:
        pytest.skip("set RELEASEGATE_AWS_KMS_CONTRACT_KEY_ID or RELEASEGATE_KMS_KEY_ID for contract test")
    context = {
        "tenant_id": "contract-tenant",
        "key_id": "contract-key",
        "table": "tenant_signing_keys",
    }
    client = AwsKMSClient(default_kms_key_id=key_id)
    plaintext, encrypted_data_key = client.generate_data_key(context=context)
    assert len(plaintext) == 32
    decrypted = client.decrypt_data_key(encrypted_data_key, context=context)
    assert decrypted == plaintext
