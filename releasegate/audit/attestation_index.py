from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.attestation.jcs import canonicalize_jcs_bytes


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compute_dsse_sha256(envelope: Dict[str, Any]) -> str:
    """
    Stable sha256 over canonical bytes of the DSSE envelope JSON object.
    This is independent of pretty-printing/whitespace on disk.
    """
    canonical = canonicalize_jcs_bytes(envelope)
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _derive_attestation_id(statement: Dict[str, Any]) -> Optional[str]:
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else None
    if not isinstance(predicate, dict):
        return None
    signature = predicate.get("signature") if isinstance(predicate.get("signature"), dict) else None
    if not isinstance(signature, dict):
        return None
    signed_payload_hash = str(signature.get("signed_payload_hash") or "").strip()
    if ":" in signed_payload_hash:
        signed_payload_hash = signed_payload_hash.split(":", 1)[1]
    signed_payload_hash = signed_payload_hash.strip().lower()
    if len(signed_payload_hash) != 64:
        return None
    return signed_payload_hash


def build_attestation_index_entry(
    *,
    envelope: Dict[str, Any],
    statement: Dict[str, Any],
    observed_at: Optional[str] = None,
) -> Dict[str, Any]:
    subject_name = None
    subject_digest = None
    subject = statement.get("subject")
    if isinstance(subject, list) and subject and isinstance(subject[0], dict):
        subject_name = subject[0].get("name")
        digest = subject[0].get("digest")
        if isinstance(digest, dict):
            subject_digest = digest.get("sha256")

    key_ids: list[str] = []
    signatures = envelope.get("signatures")
    if isinstance(signatures, list):
        for entry in signatures:
            if isinstance(entry, dict):
                kid = str(entry.get("keyid") or "").strip()
                if kid:
                    key_ids.append(kid)

    return {
        "time": str(observed_at or "").strip() or _utc_now_iso(),
        "attestation_id": _derive_attestation_id(statement),
        "subject_name": subject_name,
        "subject_digest_sha256": subject_digest,
        "key_ids": key_ids,
        "dsse_sha256": compute_dsse_sha256(envelope),
    }


def append_attestation_index_entry(*, log_path: str, entry: Dict[str, Any]) -> None:
    # JSONL append; caller owns file permissions/retention.
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")

