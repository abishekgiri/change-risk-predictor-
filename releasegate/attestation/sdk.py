from __future__ import annotations

from typing import Any, Dict

from releasegate.attestation.key_manifest import (
    key_status_from_manifest,
    public_keys_from_manifest,
    verify_key_manifest,
)
from releasegate.attestation.merkle import (
    compute_transparency_leaf_hash,
    verify_merkle_inclusion_proof,
)
from releasegate.attestation.verify import verify_attestation_payload


def verify(attestation: Dict[str, Any], public_keys_by_key_id: Dict[str, str]) -> Dict[str, Any]:
    return verify_attestation_payload(attestation, public_keys_by_key_id=public_keys_by_key_id)


def verify_with_manifest(
    attestation: Dict[str, Any],
    *,
    manifest: Dict[str, Any],
    signature_envelope: Dict[str, Any],
    trusted_root_public_keys_by_id: Dict[str, str],
) -> Dict[str, Any]:
    manifest_report = verify_key_manifest(
        manifest,
        signature_envelope,
        trusted_root_public_keys_by_id=trusted_root_public_keys_by_id,
    )
    if not manifest_report.get("ok"):
        report = {
            "schema_valid": False,
            "payload_hash_match": False,
            "trusted_issuer": False,
            "valid_signature": False,
            "errors": [f"MANIFEST_{e}" for e in (manifest_report.get("errors") or ["INVALID"])],
            "ok": False,
            "manifest": manifest_report,
        }
        return report

    key_map = public_keys_from_manifest(manifest, include_revoked=True)
    report = verify_attestation_payload(attestation, public_keys_by_key_id=key_map)
    key_id = str(report.get("key_id") or "")
    status_entry = key_status_from_manifest(manifest, key_id)
    status = str(status_entry.get("status") or "").upper()
    if report.get("valid_signature") and status == "REVOKED":
        errors = list(report.get("errors") or [])
        reason = str(status_entry.get("revoked_reason") or "key revoked")
        errors.append(f"KEY_REVOKED:{reason}")
        report["errors"] = errors
        report["trusted_issuer"] = False
    report["manifest"] = manifest_report
    report["ok"] = bool(
        manifest_report.get("ok")
        and report.get("schema_valid")
        and report.get("payload_hash_match")
        and report.get("trusted_issuer")
        and report.get("valid_signature")
    )
    return report


def get_subject(attestation: Dict[str, Any]) -> Dict[str, Any]:
    subject = attestation.get("subject") if isinstance(attestation, dict) else None
    return dict(subject) if isinstance(subject, dict) else {}


def get_decision(attestation: Dict[str, Any]) -> Dict[str, Any]:
    decision = attestation.get("decision") if isinstance(attestation, dict) else None
    return dict(decision) if isinstance(decision, dict) else {}


def compute_leaf_hash(entry: Dict[str, Any]) -> str:
    return compute_transparency_leaf_hash(entry)


def verify_inclusion_proof(proof_payload: Dict[str, Any]) -> bool:
    try:
        return verify_merkle_inclusion_proof(
            leaf_hash=str(proof_payload.get("leaf_hash") or ""),
            root_hash=str(proof_payload.get("root_hash") or ""),
            index=int(proof_payload.get("index")),
            proof=proof_payload.get("proof") or [],
        )
    except Exception:
        return False
