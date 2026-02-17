from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releasegate.attestation.canonicalize import canonicalize_json_bytes
from releasegate.attestation.crypto import parse_public_key


DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def wrap_dsse(payload_json: Dict[str, Any], signing_key: Ed25519PrivateKey, key_id: str) -> Dict[str, Any]:
    if not isinstance(payload_json, dict):
        raise ValueError("payload_json must be a JSON object")
    effective_key_id = str(key_id or "").strip()
    if not effective_key_id:
        raise ValueError("key_id is required")

    payload_bytes = canonicalize_json_bytes(payload_json)
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")
    signature = signing_key.sign(payload_bytes)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": [
            {
                "keyid": effective_key_id,
                "sig": signature_b64,
            }
        ],
    }


def verify_dsse(
    envelope: Dict[str, Any],
    public_keys_by_key_id: Dict[str, str],
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(envelope, dict):
        return False, None, "INVALID_ENVELOPE"
    if not isinstance(public_keys_by_key_id, dict):
        raise TypeError("public_keys_by_key_id must be a dict")

    payload_type = str(envelope.get("payloadType") or "")
    if payload_type != DSSE_PAYLOAD_TYPE:
        return False, None, "UNSUPPORTED_PAYLOAD_TYPE"

    payload_b64 = str(envelope.get("payload") or "")
    if not payload_b64:
        return False, None, "MISSING_PAYLOAD"

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False, None, "MISSING_SIGNATURES"
    sig_entry = signatures[0] if isinstance(signatures[0], dict) else {}

    key_id = str(sig_entry.get("keyid") or "").strip()
    if not key_id:
        return False, None, "MISSING_KEY_ID"
    signature_b64 = str(sig_entry.get("sig") or "")
    if not signature_b64:
        return False, None, "MISSING_SIGNATURE"

    try:
        payload_bytes = base64.b64decode(payload_b64.encode("ascii"), validate=True)
    except Exception:
        return False, None, "INVALID_PAYLOAD_BASE64"

    key_material = public_keys_by_key_id.get(key_id)
    if not key_material:
        return False, None, "UNKNOWN_KEY_ID"
    try:
        public_key = parse_public_key(key_material)
    except Exception:
        return False, None, "INVALID_PUBLIC_KEY"

    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except Exception:
        return False, None, "INVALID_SIGNATURE_BASE64"
    if len(signature) != 64:
        return False, None, "SIGNATURE_LEN_INVALID"

    try:
        public_key.verify(signature, payload_bytes)
    except Exception:
        return False, None, "SIGNATURE_INVALID"

    try:
        payload_json = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return False, None, "PAYLOAD_NOT_JSON"
    if not isinstance(payload_json, dict):
        return False, None, "PAYLOAD_NOT_OBJECT"

    return True, payload_json, None
