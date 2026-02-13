from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class MissingSigningKeyError(RuntimeError):
    """Raised when attestation signing key material is not configured."""


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


def load_root_private_key_from_env() -> Ed25519PrivateKey:
    raw = (os.getenv("RELEASEGATE_ROOT_SIGNING_KEY") or "").strip()
    if raw:
        return _load_ed25519_private_key_from_text(raw, env_var_name="RELEASEGATE_ROOT_SIGNING_KEY")
    raise MissingSigningKeyError(
        "MISSING_ROOT_SIGNING_KEY: RELEASEGATE_ROOT_SIGNING_KEY is required for key-manifest signing"
    )


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


def load_public_keys_map(*, key_file: Optional[str] = None) -> Dict[str, str]:
    """
    Returns mapping: key_id -> public_key_material.
    public_key_material can be PEM or base64/raw 32-byte representation.
    """
    key_map: Dict[str, str] = {}

    configured = (os.getenv("RELEASEGATE_ATTESTATION_PUBLIC_KEYS") or "").strip()
    key_id = current_key_id()

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
