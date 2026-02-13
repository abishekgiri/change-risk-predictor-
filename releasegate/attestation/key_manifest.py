from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from releasegate.attestation.canonicalize import canonicalize_json_bytes
from releasegate.attestation.crypto import (
    load_public_keys_map,
    load_root_private_key_from_env,
    parse_public_key,
    root_key_id,
    sign_bytes,
    verify_signature,
)

KEY_STATUS_ACTIVE = "ACTIVE"
KEY_STATUS_DEPRECATED = "DEPRECATED"
KEY_STATUS_REVOKED = "REVOKED"
_ALLOWED_STATUSES = {KEY_STATUS_ACTIVE, KEY_STATUS_DEPRECATED, KEY_STATUS_REVOKED}

_CACHE_LOCK = threading.Lock()
_CACHED_PAIR: Optional[Tuple[Dict[str, Any], Dict[str, Any], float]] = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_hash(value: str) -> str:
    text = str(value or "").strip()
    if ":" in text:
        algo, raw = text.split(":", 1)
        if algo.lower() == "sha256":
            return raw.strip().lower()
    return text.lower()


def _load_key_manifest_metadata() -> Dict[str, Dict[str, Any]]:
    raw = (os.getenv("RELEASEGATE_ATTESTATION_KEY_METADATA") or "").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except Exception as exc:  # pragma: no cover - guarded by config
        raise ValueError("RELEASEGATE_ATTESTATION_KEY_METADATA must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("RELEASEGATE_ATTESTATION_KEY_METADATA must be a JSON object keyed by key_id")
    out: Dict[str, Dict[str, Any]] = {}
    for key_id, value in payload.items():
        if isinstance(value, dict):
            out[str(key_id)] = value
    return out


def build_key_manifest(*, issued_at: Optional[str] = None) -> Dict[str, Any]:
    key_map = load_public_keys_map()
    metadata = _load_key_manifest_metadata()
    ts = str(issued_at or "").strip() or _utc_now_iso()

    keys: list[Dict[str, Any]] = []
    for key_id, public_key_pem in sorted(key_map.items()):
        meta = metadata.get(key_id, {})
        status = str(meta.get("status", KEY_STATUS_ACTIVE)).upper()
        if status not in _ALLOWED_STATUSES:
            status = KEY_STATUS_ACTIVE
        entry: Dict[str, Any] = {
            "key_id": key_id,
            "public_key_pem": public_key_pem,
            "created_at": str(meta.get("created_at") or ts),
            "status": status,
        }
        if status == KEY_STATUS_REVOKED:
            revoked_at = str(meta.get("revoked_at") or ts)
            revoked_reason = str(meta.get("revoked_reason") or "unspecified")
            entry["revoked_at"] = revoked_at
            entry["revoked_reason"] = revoked_reason
        keys.append(entry)

    manifest_wo_hash = {
        "manifest_version": "1",
        "issued_at": ts,
        "root_key_id": root_key_id(),
        "keys": keys,
    }
    manifest_hash = hashlib.sha256(canonicalize_json_bytes(manifest_wo_hash)).hexdigest()
    manifest = dict(manifest_wo_hash)
    manifest["manifest_hash"] = f"sha256:{manifest_hash}"
    return manifest


def sign_key_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    manifest_hash = _normalize_hash(str(manifest.get("manifest_hash") or ""))
    if not manifest_hash:
        raise ValueError("manifest_hash is required for key-manifest signing")
    private_key = load_root_private_key_from_env()
    signature = sign_bytes(private_key, manifest_hash)
    return {
        "alg": "ed25519",
        "root_key_id": root_key_id(),
        "manifest_hash": f"sha256:{manifest_hash}",
        "signature": signature,
    }


def verify_key_manifest(
    manifest: Dict[str, Any],
    signature_envelope: Dict[str, Any],
    *,
    trusted_root_public_keys_by_id: Dict[str, str],
) -> Dict[str, Any]:
    errors: list[str] = []
    hash_ok = False
    trusted_root = False
    signature_ok = False

    if not isinstance(trusted_root_public_keys_by_id, dict):
        raise TypeError("trusted_root_public_keys_by_id must be a dict of root_key_id -> public key")

    manifest_hash_claim = _normalize_hash(str(manifest.get("manifest_hash") or ""))
    manifest_wo_hash = dict(manifest)
    manifest_wo_hash.pop("manifest_hash", None)
    computed_hash = hashlib.sha256(canonicalize_json_bytes(manifest_wo_hash)).hexdigest()
    hash_ok = computed_hash == manifest_hash_claim
    if not hash_ok:
        errors.append("MANIFEST_HASH_MISMATCH")

    sig_hash = _normalize_hash(str(signature_envelope.get("manifest_hash") or ""))
    if sig_hash != computed_hash:
        errors.append("SIGNATURE_MANIFEST_HASH_MISMATCH")

    root_id = str(signature_envelope.get("root_key_id") or "")
    root_public_key = trusted_root_public_keys_by_id.get(root_id)
    if root_public_key:
        trusted_root = True
    else:
        errors.append("UNKNOWN_ROOT_KEY_ID")

    if trusted_root and hash_ok and sig_hash == computed_hash:
        try:
            root_key = parse_public_key(root_public_key)
            signature_ok = verify_signature(root_key, computed_hash, str(signature_envelope.get("signature") or ""))
            if not signature_ok:
                errors.append("MANIFEST_SIGNATURE_INVALID")
        except Exception as exc:
            signature_ok = False
            errors.append(f"MANIFEST_SIGNATURE_ERROR: {exc}")

    return {
        "manifest_hash_match": hash_ok,
        "trusted_root": trusted_root,
        "valid_signature": signature_ok,
        "errors": errors,
        "manifest_hash": f"sha256:{computed_hash}",
        "ok": bool(hash_ok and trusted_root and signature_ok and not errors),
    }


def public_keys_from_manifest(
    manifest: Dict[str, Any],
    *,
    include_revoked: bool = False,
) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for entry in manifest.get("keys") or []:
        if not isinstance(entry, dict):
            continue
        key_id = str(entry.get("key_id") or "")
        if not key_id:
            continue
        status = str(entry.get("status") or KEY_STATUS_ACTIVE).upper()
        if status == KEY_STATUS_REVOKED and not include_revoked:
            continue
        public_key = str(entry.get("public_key_pem") or "")
        if public_key:
            out[key_id] = public_key
    return out


def key_status_from_manifest(manifest: Dict[str, Any], key_id: str) -> Dict[str, Any]:
    for entry in manifest.get("keys") or []:
        if isinstance(entry, dict) and str(entry.get("key_id") or "") == str(key_id):
            return dict(entry)
    return {}


def reset_manifest_cache() -> None:
    global _CACHED_PAIR
    with _CACHE_LOCK:
        _CACHED_PAIR = None


def get_signed_key_manifest_cached(*, force_refresh: bool = False) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    global _CACHED_PAIR
    ttl_seconds = int(os.getenv("RELEASEGATE_KEY_MANIFEST_CACHE_SECONDS", "60") or "60")
    now = time.time()
    with _CACHE_LOCK:
        if (
            not force_refresh
            and _CACHED_PAIR is not None
            and now < _CACHED_PAIR[2]
        ):
            manifest, sig, _ = _CACHED_PAIR
            return deepcopy(manifest), deepcopy(sig)

        manifest = build_key_manifest()
        signature = sign_key_manifest(manifest)
        _CACHED_PAIR = (deepcopy(manifest), deepcopy(signature), now + max(ttl_seconds, 1))
        return manifest, signature
