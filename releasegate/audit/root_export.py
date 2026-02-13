from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from releasegate.attestation.canonicalize import canonical_json_bytes
from releasegate.attestation.crypto import (
    get_root_key_id,
    parse_public_key,
    sign_bytes_with_root_key,
)
from releasegate.audit.transparency import get_or_compute_transparency_root
from releasegate.storage.base import resolve_tenant_id

# Root payload versioning
ROOT_VERSION = "1"
SIG_ALG = "ed25519"


@dataclass(frozen=True)
class DailyRootRow:
    date_utc: str
    leaf_count: int
    root_hash: str  # "sha256:<hex>"
    computed_at: str  # ISO string
    engine_git_sha: Optional[str] = None
    engine_version: Optional[str] = None
    root_key_id: Optional[str] = None


def build_external_root_payload(row: DailyRootRow) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "root_version": ROOT_VERSION,
        "date_utc": row.date_utc,
        "leaf_count": int(row.leaf_count),
        "root_hash": row.root_hash,
        "computed_at": row.computed_at,
        "engine_build": {
            "git_sha": row.engine_git_sha,
            "version": row.engine_version,
        },
    }
    return payload


def sign_external_root_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Signs canonical bytes of payload (without signature field) using root key.
    """
    key_id = get_root_key_id()
    msg = canonical_json_bytes(payload)
    sig = sign_bytes_with_root_key(msg)  # raw signature bytes

    signed = dict(payload)
    signed["signature"] = {
        "alg": SIG_ALG,
        "root_key_id": key_id,
        "sig": base64.b64encode(sig).decode("ascii"),
    }
    return signed


def verify_external_root_payload(signed_payload: Dict[str, Any], root_public_key_pem: str) -> bool:
    payload = dict(signed_payload or {})
    signature = payload.pop("signature", None)
    if not isinstance(signature, dict):
        return False
    if str(signature.get("alg") or "") != SIG_ALG:
        return False
    sig_b64 = str(signature.get("sig") or "").strip()
    if not sig_b64:
        return False
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"), validate=True)
    except Exception:
        return False
    try:
        public_key = parse_public_key(root_public_key_pem)
        public_key.verify(sig, canonical_json_bytes(payload))
    except Exception:
        return False
    return True


def export_daily_root_to_path(*, date_utc: str, out_path: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    effective_tenant = resolve_tenant_id(tenant_id, allow_none=True)
    root_item = get_or_compute_transparency_root(date_utc=date_utc, tenant_id=effective_tenant)
    if not root_item:
        return None

    engine_build = root_item.get("engine_build") if isinstance(root_item.get("engine_build"), dict) else {}
    row = DailyRootRow(
        date_utc=str(root_item.get("date_utc") or date_utc),
        leaf_count=int(root_item.get("leaf_count") or 0),
        root_hash=str(root_item.get("root_hash") or ""),
        computed_at=str(root_item.get("computed_at") or ""),
        engine_git_sha=str(engine_build.get("git_sha") or "").strip() or None,
        engine_version=str(engine_build.get("version") or "").strip() or None,
        root_key_id=get_root_key_id(),
    )

    payload = build_external_root_payload(row)
    signed = sign_external_root_payload(payload)

    output_path = Path(out_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        canonical_json_bytes(signed).decode("utf-8"),
        encoding="utf-8",
    )
    return signed
