from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from releasegate.attestation.canonicalize import canonicalize_json_bytes
from releasegate.attestation.crypto import load_public_keys_map, parse_public_key, verify_signature
from releasegate.attestation.types import ReleaseAttestation, VerifyResult


def _payload_without_signature(attestation_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(attestation_payload)
    payload.pop("signature", None)
    return payload


def _normalized_hash(value: str) -> str:
    text = str(value or "").strip()
    if ":" in text:
        algo, raw = text.split(":", 1)
        if algo.lower() == "sha256":
            return raw.strip().lower()
    return text.lower()


def verify_attestation_payload(
    payload: Dict[str, Any],
    *,
    public_keys_by_key_id: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    errors: list[str] = []
    schema_valid = True
    trusted_issuer = False
    payload_hash_match = False
    valid_signature = False
    key_id: Optional[str] = None
    signed_hash_value: Optional[str] = None
    computed_hash_value: Optional[str] = None

    try:
        attestation = ReleaseAttestation.model_validate(payload)
        normalized = attestation.model_dump(mode="json")
    except Exception as exc:
        schema_valid = False
        errors.append(f"SCHEMA_INVALID: {exc}")
        return VerifyResult(
            schema_valid=False,
            payload_hash_match=False,
            trusted_issuer=False,
            valid_signature=False,
            errors=errors,
        ).model_dump(mode="json")

    key_id = attestation.issuer.key_id
    signature = attestation.signature
    signed_hash_value = _normalized_hash(signature.signed_payload_hash)

    canonical = canonicalize_json_bytes(_payload_without_signature(normalized))
    computed_hash_value = hashlib.sha256(canonical).hexdigest()
    payload_hash_match = computed_hash_value == signed_hash_value
    if not payload_hash_match:
        errors.append("PAYLOAD_HASH_MISMATCH")

    key_map = public_keys_by_key_id or load_public_keys_map()
    public_key_material = (key_map or {}).get(key_id)
    if public_key_material:
        trusted_issuer = True
    else:
        errors.append("UNKNOWN_KEY_ID")

    if trusted_issuer and payload_hash_match:
        try:
            public_key = parse_public_key(public_key_material)
            valid_signature = verify_signature(public_key, computed_hash_value, signature.signature_bytes)
            if not valid_signature:
                errors.append("SIGNATURE_INVALID")
        except Exception as exc:
            valid_signature = False
            errors.append(f"SIGNATURE_ERROR: {exc}")

    return VerifyResult(
        schema_valid=schema_valid,
        payload_hash_match=payload_hash_match,
        trusted_issuer=trusted_issuer,
        valid_signature=valid_signature,
        errors=errors,
        signed_payload_hash=f"sha256:{signed_hash_value}" if signed_hash_value else None,
        computed_payload_hash=f"sha256:{computed_hash_value}" if computed_hash_value else None,
        key_id=key_id,
    ).model_dump(mode="json")
