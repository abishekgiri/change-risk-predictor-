from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releasegate.attestation.jcs import canonicalize_jcs_bytes
from releasegate.attestation.crypto import parse_public_key


DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
DSSE_SIGSTORE_KEY_ID = "sigstore"


class SigstoreSigningError(RuntimeError):
    pass


def wrap_dsse(payload_json: Dict[str, Any], signing_key: Ed25519PrivateKey, key_id: str) -> Dict[str, Any]:
    if not isinstance(payload_json, dict):
        raise ValueError("payload_json must be a JSON object")
    effective_key_id = str(key_id or "").strip()
    if not effective_key_id:
        raise ValueError("key_id is required")

    payload_bytes = canonicalize_jcs_bytes(payload_json)
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


def wrap_dsse_sigstore(
    payload_json: Dict[str, Any],
    *,
    bundle_path: str,
    key_id: str = DSSE_SIGSTORE_KEY_ID,
    cosign_exe: str = "cosign",
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Sign DSSE payload bytes using Sigstore keyless signing via `cosign sign-blob`,
    writing a Sigstore bundle JSON to bundle_path.

    This requires `cosign` to be installed in PATH and typically requires the caller
    to run in an environment with OIDC identity available (e.g., GitHub Actions with
    id-token: write).
    """
    if not isinstance(payload_json, dict):
        raise ValueError("payload_json must be a JSON object")
    bundle_path = str(bundle_path or "").strip()
    if not bundle_path:
        raise ValueError("bundle_path is required")

    effective_key_id = str(key_id or "").strip() or DSSE_SIGSTORE_KEY_ID

    payload_bytes = canonicalize_jcs_bytes(payload_json)
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

    # cosign operates on files; write deterministic bytes and sign them.
    with tempfile.TemporaryDirectory() as td:
        payload_file = os.path.join(td, "payload.json")
        with open(payload_file, "wb") as f:
            f.write(payload_bytes)

        proc_env = dict(os.environ)
        if env:
            proc_env.update({str(k): str(v) for k, v in env.items()})

        try:
            proc = subprocess.run(
                [cosign_exe, "sign-blob", "--yes", "--bundle", bundle_path, payload_file],
                capture_output=True,
                text=True,
                env=proc_env,
            )
        except FileNotFoundError as exc:
            raise SigstoreSigningError("cosign not found in PATH") from exc

        if proc.returncode != 0:
            raise SigstoreSigningError((proc.stderr or proc.stdout or "").strip() or "cosign sign-blob failed")

        # cosign prints the signature to stdout (base64). Take the last non-empty line.
        lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
        signature_b64 = lines[-1] if lines else ""
        if not signature_b64:
            raise SigstoreSigningError("cosign did not emit a signature")

        # Basic sanity check: signature must be valid base64.
        try:
            base64.b64decode(signature_b64.encode("ascii"), validate=True)
        except Exception as exc:
            raise SigstoreSigningError("cosign signature is not valid base64") from exc

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


def verify_dsse_sigstore(
    envelope: Dict[str, Any],
    *,
    bundle_path: str,
    certificate_identity: Optional[str] = None,
    certificate_oidc_issuer: Optional[str] = None,
    cosign_exe: str = "cosign",
    env: Optional[Dict[str, str]] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Verify DSSE payload bytes using a Sigstore bundle via `cosign verify-blob`.
    Returns (valid, payload_json, error_code).
    """
    if not isinstance(envelope, dict):
        return False, None, "INVALID_ENVELOPE"

    payload_type = str(envelope.get("payloadType") or "")
    if payload_type != DSSE_PAYLOAD_TYPE:
        return False, None, "UNSUPPORTED_PAYLOAD_TYPE"

    payload_b64 = str(envelope.get("payload") or "")
    if not payload_b64:
        return False, None, "MISSING_PAYLOAD"

    bundle_path = str(bundle_path or "").strip()
    if not bundle_path:
        return False, None, "MISSING_SIGSTORE_BUNDLE"

    try:
        payload_bytes = base64.b64decode(payload_b64.encode("ascii"), validate=True)
    except Exception:
        return False, None, "INVALID_PAYLOAD_BASE64"

    with tempfile.TemporaryDirectory() as td:
        payload_file = os.path.join(td, "payload.json")
        with open(payload_file, "wb") as f:
            f.write(payload_bytes)

        cmd = [cosign_exe, "verify-blob", "--bundle", bundle_path]
        if certificate_identity:
            cmd += ["--certificate-identity", str(certificate_identity)]
        if certificate_oidc_issuer:
            cmd += ["--certificate-oidc-issuer", str(certificate_oidc_issuer)]
        cmd.append(payload_file)

        proc_env = dict(os.environ)
        if env:
            proc_env.update({str(k): str(v) for k, v in env.items()})

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, env=proc_env)
        except FileNotFoundError:
            return False, None, "COSIGN_NOT_FOUND"

        if proc.returncode != 0:
            return False, None, "SIGSTORE_SIGNATURE_INVALID"

    try:
        parsed = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return False, None, "PAYLOAD_NOT_JSON"
    if not isinstance(parsed, dict):
        return False, None, "PAYLOAD_NOT_OBJECT"

    return True, parsed, None


def wrap_dsse_multi(
    payload_json: Dict[str, Any],
    *,
    signers: List[Tuple[str, Ed25519PrivateKey]],
) -> Dict[str, Any]:
    if not isinstance(payload_json, dict):
        raise ValueError("payload_json must be a JSON object")
    if not isinstance(signers, list) or not signers:
        raise ValueError("signers must be a non-empty list of (key_id, signing_key)")

    payload_bytes = canonicalize_jcs_bytes(payload_json)
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

    signatures: list[dict] = []
    for key_id, signing_key in signers:
        effective_key_id = str(key_id or "").strip()
        if not effective_key_id:
            raise ValueError("key_id is required for each signer")
        if signing_key is None:
            raise ValueError(f"signing_key is required for signer {effective_key_id}")
        sig = signing_key.sign(payload_bytes)
        signatures.append(
            {
                "keyid": effective_key_id,
                "sig": base64.b64encode(sig).decode("ascii"),
            }
        )

    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": signatures,
    }


def verify_dsse_signatures(
    envelope: Dict[str, Any],
    public_keys_by_key_id: Dict[str, str],
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], Optional[str]]:
    """
    Verifies all signatures in a DSSE envelope.
    Returns (payload_json, signature_results, error_code).

    signature_results entries include:
      - keyid
      - ok (bool)
      - error_code (optional)
    """
    if not isinstance(envelope, dict):
        return None, [], "INVALID_ENVELOPE"
    if not isinstance(public_keys_by_key_id, dict):
        raise TypeError("public_keys_by_key_id must be a dict")

    payload_type = str(envelope.get("payloadType") or "")
    if payload_type != DSSE_PAYLOAD_TYPE:
        return None, [], "UNSUPPORTED_PAYLOAD_TYPE"

    payload_b64 = str(envelope.get("payload") or "")
    if not payload_b64:
        return None, [], "MISSING_PAYLOAD"

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return None, [], "MISSING_SIGNATURES"

    try:
        payload_bytes = base64.b64decode(payload_b64.encode("ascii"), validate=True)
    except Exception:
        return None, [], "INVALID_PAYLOAD_BASE64"

    payload_json: Optional[Dict[str, Any]] = None
    results: list[dict] = []
    for entry in signatures:
        if not isinstance(entry, dict):
            results.append({"keyid": None, "ok": False, "error_code": "INVALID_SIGNATURE_ENTRY"})
            continue
        key_id = str(entry.get("keyid") or "").strip()
        if not key_id:
            results.append({"keyid": None, "ok": False, "error_code": "MISSING_KEY_ID"})
            continue
        signature_b64 = str(entry.get("sig") or "")
        if not signature_b64:
            results.append({"keyid": key_id, "ok": False, "error_code": "MISSING_SIGNATURE"})
            continue

        key_material = public_keys_by_key_id.get(key_id)
        if not key_material:
            results.append({"keyid": key_id, "ok": False, "error_code": "UNKNOWN_KEY_ID"})
            continue
        try:
            public_key = parse_public_key(key_material)
        except Exception:
            results.append({"keyid": key_id, "ok": False, "error_code": "INVALID_PUBLIC_KEY"})
            continue

        try:
            signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        except Exception:
            results.append({"keyid": key_id, "ok": False, "error_code": "INVALID_SIGNATURE_BASE64"})
            continue
        if len(signature) != 64:
            results.append({"keyid": key_id, "ok": False, "error_code": "SIGNATURE_LEN_INVALID"})
            continue

        try:
            public_key.verify(signature, payload_bytes)
            results.append({"keyid": key_id, "ok": True})
        except Exception:
            results.append({"keyid": key_id, "ok": False, "error_code": "SIGNATURE_INVALID"})

    if any(r.get("ok") is True for r in results):
        try:
            parsed = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return None, results, "PAYLOAD_NOT_JSON"
        if not isinstance(parsed, dict):
            return None, results, "PAYLOAD_NOT_OBJECT"
        payload_json = parsed

    return payload_json, results, None


def verify_dsse(
    envelope: Dict[str, Any],
    public_keys_by_key_id: Dict[str, str],
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(envelope, dict):
        return False, None, "INVALID_ENVELOPE"
    if not isinstance(public_keys_by_key_id, dict):
        raise TypeError("public_keys_by_key_id must be a dict")

    payload_json, results, error = verify_dsse_signatures(envelope, public_keys_by_key_id)
    if error:
        return False, None, error
    if not results:
        return False, None, "MISSING_SIGNATURES"

    # Back-compat: verify only the first signature for legacy callers.
    first = results[0]
    if first.get("ok") is True:
        return True, payload_json, None
    return False, None, str(first.get("error_code") or "SIGNATURE_INVALID")
