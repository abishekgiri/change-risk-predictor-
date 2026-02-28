from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, Optional, Tuple

from releasegate.utils.canonical import canonical_json


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(str(value or "").encode("ascii"), validate=True)


def _aws_context(context: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    if not isinstance(context, dict) or not context:
        return None
    mapped: Dict[str, str] = {}
    for key, raw_value in sorted(context.items()):
        text_key = str(key or "").strip()
        if not text_key:
            continue
        if raw_value is None:
            continue
        if isinstance(raw_value, (str, int, float, bool)):
            mapped[text_key] = str(raw_value)
        else:
            mapped[text_key] = canonical_json(raw_value)
    return mapped or None


def _build_aws_kms_client(*, region_name: Optional[str], endpoint_url: Optional[str]):
    try:
        import boto3  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on runtime package set
        raise RuntimeError(
            "AWS KMS mode requires boto3. Install boto3 to use RELEASEGATE_KMS_MODE=aws."
        ) from exc

    config = None
    try:
        from botocore.config import Config  # type: ignore

        max_attempts = max(1, int(os.getenv("RELEASEGATE_AWS_KMS_MAX_ATTEMPTS", "3")))
        connect_timeout = max(0.1, float(os.getenv("RELEASEGATE_AWS_KMS_CONNECT_TIMEOUT_SECONDS", "2")))
        read_timeout = max(0.1, float(os.getenv("RELEASEGATE_AWS_KMS_READ_TIMEOUT_SECONDS", "10")))
        config = Config(
            retries={
                "max_attempts": max_attempts,
                "mode": "standard",
            },
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )
    except Exception:
        config = None

    kwargs: Dict[str, Any] = {}
    if region_name:
        kwargs["region_name"] = region_name
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    if config is not None:
        kwargs["config"] = config
    return boto3.client("kms", **kwargs)


class AwsKMSClient:
    def __init__(
        self,
        *,
        default_kms_key_id: str,
        region_name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        client: Any = None,
    ) -> None:
        self.default_kms_key_id = str(default_kms_key_id or "").strip()
        self.region_name = (
            str(region_name or "").strip()
            or str(os.getenv("RELEASEGATE_AWS_KMS_REGION") or "").strip()
            or str(os.getenv("AWS_REGION") or "").strip()
            or str(os.getenv("AWS_DEFAULT_REGION") or "").strip()
            or None
        )
        self.endpoint_url = (
            str(endpoint_url or "").strip()
            or str(os.getenv("RELEASEGATE_AWS_KMS_ENDPOINT_URL") or "").strip()
            or None
        )
        self._client = client or _build_aws_kms_client(
            region_name=self.region_name,
            endpoint_url=self.endpoint_url,
        )

    def _resolve_key_id(self, kms_key_id: Optional[str]) -> str:
        key_id = str(kms_key_id or self.default_kms_key_id or "").strip()
        if not key_id:
            raise ValueError("kms_key_id is required for AWS KMS operations")
        return key_id

    def generate_data_key(
        self,
        *,
        kms_key_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bytes, str]:
        key_id = self._resolve_key_id(kms_key_id)
        request: Dict[str, Any] = {
            "KeyId": key_id,
            "KeySpec": "AES_256",
        }
        encryption_context = _aws_context(context)
        if encryption_context:
            request["EncryptionContext"] = encryption_context
        response = self._client.generate_data_key(**request)
        plaintext = bytes(response.get("Plaintext") or b"")
        ciphertext_blob = bytes(response.get("CiphertextBlob") or b"")
        if len(plaintext) != 32:
            raise ValueError("AWS KMS GenerateDataKey returned an invalid plaintext key length")
        if not ciphertext_blob:
            raise ValueError("AWS KMS GenerateDataKey returned an empty CiphertextBlob")
        payload = {
            "v": 1,
            "mode": "aws",
            "kms_key_id": key_id,
            "ciphertext_blob": _b64e(ciphertext_blob),
        }
        return plaintext, canonical_json(payload)

    def decrypt_data_key(
        self,
        encrypted_key: str,
        *,
        kms_key_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        payload = json.loads(str(encrypted_key or "{}"))
        if not isinstance(payload, dict):
            raise ValueError("encrypted data key payload must be an object")
        mode = str(payload.get("mode") or "").strip().lower()
        if mode and mode != "aws":
            raise ValueError(f"encrypted data key mode '{mode}' is not supported by AWS client")
        ciphertext_blob_raw = str(payload.get("ciphertext_blob") or "").strip()
        if not ciphertext_blob_raw:
            raise ValueError("encrypted data key payload is missing ciphertext_blob")
        stored_kms_key_id = str(payload.get("kms_key_id") or "").strip()
        resolved_kms_key_id = self._resolve_key_id(kms_key_id or stored_kms_key_id)
        if stored_kms_key_id and stored_kms_key_id != resolved_kms_key_id:
            raise ValueError("KMS key mismatch while decrypting data key")

        request: Dict[str, Any] = {
            "CiphertextBlob": _b64d(ciphertext_blob_raw),
            "KeyId": resolved_kms_key_id,
        }
        encryption_context = _aws_context(context)
        if encryption_context:
            request["EncryptionContext"] = encryption_context
        response = self._client.decrypt(**request)
        plaintext = bytes(response.get("Plaintext") or b"")
        if len(plaintext) != 32:
            raise ValueError("AWS KMS Decrypt returned an invalid plaintext key length")
        return plaintext

    def _resolve_signing_key_id(self, key_id: str) -> str:
        requested = str(key_id or "").strip()
        if not requested:
            raise ValueError("key_id is required for KMS sign operations")
        mapping_raw = str(os.getenv("RELEASEGATE_AWS_KMS_SIGNING_KEYS") or "").strip()
        if not mapping_raw:
            return requested
        mapping = json.loads(mapping_raw)
        if not isinstance(mapping, dict):
            raise ValueError("RELEASEGATE_AWS_KMS_SIGNING_KEYS must be a JSON object")
        resolved = mapping.get(requested)
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip()
        return requested

    def sign(
        self,
        *,
        key_id: str,
        payload: bytes,
    ) -> bytes:
        resolved_key_id = self._resolve_signing_key_id(key_id)
        signing_algorithm = str(os.getenv("RELEASEGATE_AWS_KMS_SIGNING_ALGORITHM") or "EDDSA").strip() or "EDDSA"
        response = self._client.sign(
            KeyId=resolved_key_id,
            Message=bytes(payload),
            MessageType="RAW",
            SigningAlgorithm=signing_algorithm,
        )
        signature = bytes(response.get("Signature") or b"")
        if not signature:
            raise ValueError("AWS KMS Sign returned an empty signature")
        return signature
