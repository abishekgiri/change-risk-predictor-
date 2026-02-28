from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class MissingSigningKeyError(RuntimeError):
    """Raised when attestation signing key material is not configured."""


class MissingRootSigningKeyError(MissingSigningKeyError):
    """Raised when root signing key material is not configured."""


def _load_ed25519_private_key_from_text(raw: str, *, env_var_name: str) -> Ed25519PrivateKey:
    if raw.startswith("-----BEGIN"):
        try:
            loaded = serialization.load_pem_private_key(raw.encode("utf-8"), password=None)
        except Exception as exc:
            raise ValueError(
                f"Invalid signing key format for {env_var_name}: expected Ed25519 PEM or 32-byte raw key"
            ) from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"{env_var_name} must be an Ed25519 private key")
        return loaded

    material = _decode_key_material(raw)
    if len(material) != 32:
        raise ValueError(f"Invalid signing key format: {env_var_name} must decode to 32 raw bytes for Ed25519")
    return Ed25519PrivateKey.from_private_bytes(material)


def _decode_key_material(raw_value: str) -> bytes:
    value = (raw_value or "").strip()
    if not value:
        raise ValueError("empty key material")

    if value.startswith("-----BEGIN"):
        raise ValueError("PEM key must be loaded via dedicated PEM parser")

    if len(value) == 64:
        try:
            return bytes.fromhex(value)
        except ValueError:
            pass

    try:
        decoded = base64.b64decode(value, validate=True)
        if decoded:
            return decoded
    except Exception:
        pass

    return value.encode("utf-8")


def load_private_key_from_env() -> Ed25519PrivateKey:
    raw = (os.getenv("RELEASEGATE_SIGNING_KEY") or "").strip()
    if raw:
        return _load_ed25519_private_key_from_text(raw, env_var_name="RELEASEGATE_SIGNING_KEY")

    raise MissingSigningKeyError(
        "MISSING_SIGNING_KEY: RELEASEGATE_SIGNING_KEY is required for attestation signing"
    )


def current_key_id() -> str:
    return (os.getenv("RELEASEGATE_ATTESTATION_KEY_ID") or "rg-local-2026-01").strip()


def root_key_id() -> str:
    return (os.getenv("RELEASEGATE_ROOT_KEY_ID") or "rg-root-2026-01").strip()


def get_root_key_id() -> str:
    return root_key_id()


def load_root_private_key_from_env() -> Ed25519PrivateKey:
    raw = (os.getenv("RELEASEGATE_ROOT_SIGNING_KEY") or "").strip()
    if raw:
        return _load_ed25519_private_key_from_text(raw, env_var_name="RELEASEGATE_ROOT_SIGNING_KEY")
    raise MissingRootSigningKeyError(
        "MISSING_ROOT_SIGNING_KEY: RELEASEGATE_ROOT_SIGNING_KEY is required for root signing operations "
        "(key manifest + external root export). Expected Ed25519 PEM or 32-byte raw key (hex/base64)."
    )


def sign_bytes_with_root_key(message: bytes) -> bytes:
    private_key = load_root_private_key_from_env()
    return private_key.sign(bytes(message))


def public_key_pem_from_private(private_key: Ed25519PrivateKey) -> str:
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _load_public_key_pem(value: str) -> Ed25519PublicKey:
    loaded = serialization.load_pem_public_key(value.encode("utf-8"))
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return loaded


def _load_public_key_from_raw(value: str) -> Ed25519PublicKey:
    material = _decode_key_material(value)
    if len(material) != 32:
        raise ValueError("public key material must decode to 32 bytes")
    return Ed25519PublicKey.from_public_bytes(material)


def parse_public_key(value: str) -> Ed25519PublicKey:
    if (value or "").strip().startswith("-----BEGIN"):
        return _load_public_key_pem(value)
    return _load_public_key_from_raw(value)


def load_private_key_for_tenant(tenant_id: Optional[str]) -> Tuple[Ed25519PrivateKey, str]:
    effective_tenant = str(tenant_id or "").strip()
    if effective_tenant:
        from releasegate.tenants.keys import get_active_tenant_signing_key_record

        record = get_active_tenant_signing_key_record(
            effective_tenant,
            actor="system:attestation",
            purpose="attestation_signing",
            access_operation="sign",
        )
        if isinstance(record, dict):
            key_id = str(record.get("key_id") or "").strip()
            private_key = str(record.get("private_key") or "").strip()
            if key_id and private_key:
                loaded = _load_ed25519_private_key_from_text(
                    private_key,
                    env_var_name=f"tenant_signing_keys[{effective_tenant}]",
                )
                return loaded, key_id
    return load_private_key_from_env(), current_key_id()


def _load_keys_from_tenant_store(
    *,
    tenant_id: Optional[str],
    include_verify_only: bool,
    include_revoked: bool,
) -> Dict[str, str]:
    effective_tenant = str(tenant_id or "").strip()
    if not effective_tenant:
        return {}
    try:
        from releasegate.tenants.keys import get_tenant_signing_public_keys_with_status

        key_records = get_tenant_signing_public_keys_with_status(
            tenant_id=effective_tenant,
            include_verify_only=include_verify_only,
            include_revoked=include_revoked,
        )
    except Exception:
        return {}
    key_map: Dict[str, str] = {}
    for key_id, item in key_records.items():
        if not isinstance(item, dict):
            continue
        public_key = str(item.get("public_key") or "").strip()
        if not public_key:
            continue
        key_map[str(key_id)] = public_key
    return key_map


def load_public_keys_map(
    *,
    key_file: Optional[str] = None,
    tenant_id: Optional[str] = None,
    include_verify_only: bool = True,
    include_revoked: bool = False,
) -> Dict[str, str]:
    """
    Returns mapping: key_id -> public_key_material.
    public_key_material can be PEM or base64/raw 32-byte representation.
    Resolution order:
      1) tenant signing keys (if tenant_id provided and keys exist)
      2) explicit key_file
      3) RELEASEGATE_ATTESTATION_PUBLIC_KEYS / default file fallback
    """
    key_map: Dict[str, str] = {}

    configured = (os.getenv("RELEASEGATE_ATTESTATION_PUBLIC_KEYS") or "").strip()
    key_id = current_key_id()

    tenant_keys = _load_keys_from_tenant_store(
        tenant_id=tenant_id,
        include_verify_only=include_verify_only,
        include_revoked=include_revoked,
    )
    if tenant_keys:
        return tenant_keys

    def _consume_payload(raw_text: str) -> None:
        text = raw_text.strip()
        if not text:
            return
        if text.startswith("{"):
            payload = json.loads(text)
            if not isinstance(payload, dict):
                raise ValueError("RELEASEGATE_ATTESTATION_PUBLIC_KEYS JSON must be an object")
            for k, v in payload.items():
                if isinstance(v, str) and v.strip():
                    key_map[str(k)] = v.strip()
            return
        key_map[key_id] = text

    if key_file:
        _consume_payload(Path(key_file).read_text(encoding="utf-8"))
        return key_map

    if configured:
        try:
            maybe_path = Path(configured)
            if maybe_path.exists():
                _consume_payload(maybe_path.read_text(encoding="utf-8"))
            else:
                _consume_payload(configured)
        except OSError:
            _consume_payload(configured)
        return key_map

    default_public_path = Path("attestation/keys/public.pem")
    if default_public_path.exists():
        key_map[key_id] = default_public_path.read_text(encoding="utf-8").strip()

    return key_map


def sign_bytes(private_key: Ed25519PrivateKey, payload_hash_hex: str) -> str:
    signature = private_key.sign(bytes.fromhex(payload_hash_hex))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(public_key: Ed25519PublicKey, payload_hash_hex: str, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        public_key.verify(signature, bytes.fromhex(payload_hash_hex))
        return True
    except Exception:
        return False
