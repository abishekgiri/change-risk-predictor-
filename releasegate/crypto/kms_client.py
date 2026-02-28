from __future__ import annotations

import base64
import hashlib
import json
import os
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from releasegate.utils.canonical import canonical_json


KMS_ENVELOPE_MODE = "kms_envelope_v1"
LOCAL_KMS_DIRECT_MODE = "kms_direct_v1"
_CLOUD_KMS_MODES = {"aws", "gcp", "azure"}


def _utc_env() -> str:
    return str(os.getenv("RELEASEGATE_ENV") or "development").strip().lower()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _decode_material(raw_value: str) -> bytes:
    value = str(raw_value or "").strip()
    if not value:
        raise ValueError("empty key material")
    if len(value) == 64:
        try:
            return bytes.fromhex(value)
        except Exception:
            pass
    try:
        decoded = base64.b64decode(value, validate=True)
        if decoded:
            return decoded
    except Exception:
        pass
    return value.encode("utf-8")


def _parse_ed25519_private_key(raw_key: str) -> Ed25519PrivateKey:
    value = str(raw_key or "").strip()
    if not value:
        raise ValueError("private key is required")
    if value.startswith("-----BEGIN"):
        loaded = serialization.load_pem_private_key(value.encode("utf-8"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("private key must be Ed25519")
        return loaded
    material = _decode_material(value)
    if len(material) != 32:
        raise ValueError("private key must decode to 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(material)


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(str(value or "").encode("ascii"), validate=True)


def _aad_bytes(context: Optional[Dict[str, Any]]) -> bytes:
    if not isinstance(context, dict) or not context:
        return b""
    return canonical_json(context).encode("utf-8")


def _wipe(secret: bytearray) -> None:
    for index in range(len(secret)):
        secret[index] = 0


class KMSClient(ABC):
    @abstractmethod
    def generate_data_key(
        self,
        *,
        kms_key_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bytes, str]:
        raise NotImplementedError

    @abstractmethod
    def decrypt_data_key(
        self,
        encrypted_key: str,
        *,
        kms_key_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def sign(
        self,
        *,
        key_id: str,
        payload: bytes,
    ) -> bytes:
        raise NotImplementedError


class LocalKMSClient(KMSClient):
    def __init__(self, *, default_kms_key_id: str) -> None:
        self.default_kms_key_id = str(default_kms_key_id or "releasegate-local-kms").strip()
        raw = str(os.getenv("RELEASEGATE_LOCAL_KMS_WRAPPING_KEY") or "").strip()
        if raw:
            wrapping_key = _decode_material(raw)
            if len(wrapping_key) != 32:
                raise ValueError("RELEASEGATE_LOCAL_KMS_WRAPPING_KEY must decode to 32 bytes")
        else:
            env = _utc_env()
            if env not in {"dev", "development", "test"}:
                raise ValueError(
                    "RELEASEGATE_LOCAL_KMS_WRAPPING_KEY must be set when RELEASEGATE_KMS_MODE=local in non-dev environments"
                )
            seed = str(os.getenv("RELEASEGATE_JWT_SECRET") or "releasegate-local-dev").encode("utf-8")
            wrapping_key = hashlib.sha256(seed).digest()
        self._wrapping_key = bytes(wrapping_key)

    def _key_id(self, kms_key_id: Optional[str]) -> str:
        return str(kms_key_id or self.default_kms_key_id).strip() or self.default_kms_key_id

    def generate_data_key(
        self,
        *,
        kms_key_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bytes, str]:
        data_key = os.urandom(32)
        nonce = os.urandom(12)
        aad = _aad_bytes(
            {
                "kms_key_id": self._key_id(kms_key_id),
                "context": context or {},
            }
        )
        ciphertext = AESGCM(self._wrapping_key).encrypt(nonce, data_key, aad)
        payload = {
            "v": 1,
            "alg": "AES-256-GCM",
            "mode": "local",
            "kms_key_id": self._key_id(kms_key_id),
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        }
        return data_key, canonical_json(payload)

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
        nonce = _b64d(str(payload.get("nonce") or ""))
        ciphertext = _b64d(str(payload.get("ciphertext") or ""))
        stored_kms_key_id = str(payload.get("kms_key_id") or "").strip()
        expected_kms_key_id = self._key_id(kms_key_id)
        if stored_kms_key_id and stored_kms_key_id != expected_kms_key_id:
            raise ValueError("KMS key mismatch while decrypting data key")
        aad = _aad_bytes(
            {
                "kms_key_id": stored_kms_key_id or expected_kms_key_id,
                "context": context or {},
            }
        )
        return AESGCM(self._wrapping_key).decrypt(nonce, ciphertext, aad)

    def sign(
        self,
        *,
        key_id: str,
        payload: bytes,
    ) -> bytes:
        mapping_raw = str(os.getenv("RELEASEGATE_KMS_DIRECT_SIGNING_KEYS") or "").strip()
        if not mapping_raw:
            raise ValueError("RELEASEGATE_KMS_DIRECT_SIGNING_KEYS must be configured for kms_direct signing")
        payload_map = json.loads(mapping_raw)
        if not isinstance(payload_map, dict):
            raise ValueError("RELEASEGATE_KMS_DIRECT_SIGNING_KEYS must be a JSON object")
        raw_key = payload_map.get(str(key_id))
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise ValueError(f"kms_direct signing key '{key_id}' not configured")
        private_key = _parse_ed25519_private_key(raw_key)
        return private_key.sign(bytes(payload))


def _kms_mode() -> str:
    return str(os.getenv("RELEASEGATE_KMS_MODE") or "local").strip().lower()


def strict_kms_required() -> bool:
    return _env_bool("RELEASEGATE_STRICT_KMS", False)


def allow_legacy_key_material() -> bool:
    return not strict_kms_required()


def ensure_kms_runtime_policy() -> None:
    mode = _kms_mode()
    if strict_kms_required() and mode not in _CLOUD_KMS_MODES:
        raise RuntimeError(
            "RELEASEGATE_STRICT_KMS is enabled but RELEASEGATE_KMS_MODE is not a cloud provider. "
            "Set RELEASEGATE_KMS_MODE to aws, gcp, or azure."
        )
    if mode in _CLOUD_KMS_MODES:
        raise RuntimeError(
            f"RELEASEGATE_KMS_MODE={mode} is configured but cloud adapter is not implemented in this build."
        )


@lru_cache(maxsize=1)
def get_kms_client() -> KMSClient:
    ensure_kms_runtime_policy()
    mode = _kms_mode()
    default_kms_key_id = str(os.getenv("RELEASEGATE_KMS_KEY_ID") or "releasegate-local-kms").strip()
    if mode in {"local", "mock"}:
        return LocalKMSClient(default_kms_key_id=default_kms_key_id)
    raise ValueError(f"Unsupported RELEASEGATE_KMS_MODE '{mode}'. Supported modes: local, mock, aws, gcp, azure.")


def kms_envelope_encrypt(
    plaintext: bytes,
    *,
    kms_key_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    kms_client = get_kms_client()
    data_key, encrypted_data_key = kms_client.generate_data_key(kms_key_id=kms_key_id, context=context)
    key_buffer = bytearray(data_key)
    try:
        nonce = os.urandom(12)
        aad = _aad_bytes(context)
        ciphertext = AESGCM(bytes(key_buffer)).encrypt(nonce, bytes(plaintext), aad)
    finally:
        _wipe(key_buffer)

    cipher_payload = {
        "v": 1,
        "alg": "AES-256-GCM",
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }
    return {
        "encryption_mode": KMS_ENVELOPE_MODE,
        "ciphertext": canonical_json(cipher_payload),
        "encrypted_data_key": encrypted_data_key,
        "kms_key_id": str(kms_key_id or os.getenv("RELEASEGATE_KMS_KEY_ID") or "").strip(),
    }


def kms_envelope_decrypt(
    *,
    ciphertext: str,
    encrypted_data_key: str,
    kms_key_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> bytes:
    kms_client = get_kms_client()
    data_key = kms_client.decrypt_data_key(
        encrypted_data_key,
        kms_key_id=kms_key_id,
        context=context,
    )
    key_buffer = bytearray(data_key)
    try:
        payload = json.loads(str(ciphertext or "{}"))
        if not isinstance(payload, dict):
            raise ValueError("ciphertext payload must be a JSON object")
        nonce = _b64d(str(payload.get("nonce") or ""))
        encrypted_payload = _b64d(str(payload.get("ciphertext") or ""))
        aad = _aad_bytes(context)
        plaintext = AESGCM(bytes(key_buffer)).decrypt(nonce, encrypted_payload, aad)
    finally:
        _wipe(key_buffer)
    return plaintext
