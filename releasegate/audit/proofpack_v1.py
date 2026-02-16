from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from releasegate.attestation.canonicalize import canonicalize_attestation, canonicalize_json_bytes
from releasegate.attestation.crypto import load_public_keys_map
from releasegate.attestation.sdk import verify_inclusion_proof
from releasegate.attestation.verify import verify_attestation_payload
from releasegate.audit.rfc3161 import verify_rfc3161_artifact


PROOFPACK_VERSION = "v1"
MANIFEST_PATH = "manifest.json"
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

REQUIRED_BASE_ORDER: Tuple[str, ...] = (
    "attestation.json",
    "signature.txt",
    "inputs.json",
    "decision.json",
)
OPTIONAL_ORDER: Tuple[str, ...] = (
    "receipt.json",
    "inclusion_proof.json",
    "timestamp.json",
    "rfc3161.tsr",
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_hash(raw: str) -> str:
    text = str(raw or "").strip()
    if ":" in text:
        algo, value = text.split(":", 1)
        if algo.strip().lower() != "sha256":
            raise ValueError("hash must use sha256")
        text = value
    text = text.strip().lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError("hash must be 64 lowercase hex chars")
    return text


def _ordered_paths(include_receipt: bool, include_inclusion: bool, include_timestamp: bool, include_tsr: bool) -> List[str]:
    ordered: List[str] = [
        "attestation.json",
        "signature.txt",
    ]
    if include_receipt:
        ordered.append("receipt.json")
    ordered.extend(("inputs.json", "decision.json", MANIFEST_PATH))
    if include_inclusion:
        ordered.append("inclusion_proof.json")
    if include_timestamp:
        ordered.append("timestamp.json")
    if include_tsr:
        ordered.append("rfc3161.tsr")
    return ordered


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename=path, date_time=_ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o100644 << 16
    info.create_system = 3
    return info


def _manifest_payload(
    *,
    created_by: str,
    attestation_hash: str,
    payload_hash: str,
    ordered_paths: Sequence[str],
    file_bytes: Mapping[str, bytes],
) -> Dict[str, Any]:
    files: List[Dict[str, Any]] = []
    for path in ordered_paths:
        if path == MANIFEST_PATH:
            continue
        data = file_bytes[path]
        files.append(
            {
                "path": path,
                "sha256": f"sha256:{_sha256_hex(data)}",
                "size_bytes": len(data),
            }
        )
    return {
        "proofpack_version": PROOFPACK_VERSION,
        "created_by": str(created_by or "").strip() or "unknown",
        "attestation_hash": _normalize_hash(attestation_hash),
        "payload_hash": _normalize_hash(payload_hash),
        "files": files,
    }


def build_proofpack_v1_zip_bytes(
    *,
    attestation: Mapping[str, Any],
    signature_text: str,
    inputs: Mapping[str, Any],
    decision: Mapping[str, Any],
    created_by: str,
    receipt: Optional[Mapping[str, Any]] = None,
    inclusion_proof: Optional[Mapping[str, Any]] = None,
    timestamp_metadata: Optional[Mapping[str, Any]] = None,
    rfc3161_token: Optional[bytes] = None,
) -> bytes:
    attestation_obj = dict(attestation)
    attestation_bytes = canonicalize_attestation(attestation_obj)
    signature_bytes = str(signature_text or "").encode("utf-8")
    inputs_bytes = canonicalize_json_bytes(dict(inputs))
    decision_bytes = canonicalize_json_bytes(dict(decision))

    file_bytes: Dict[str, bytes] = {
        "attestation.json": attestation_bytes,
        "signature.txt": signature_bytes,
        "inputs.json": inputs_bytes,
        "decision.json": decision_bytes,
    }
    if receipt is not None:
        file_bytes["receipt.json"] = canonicalize_json_bytes(dict(receipt))
    if inclusion_proof is not None:
        file_bytes["inclusion_proof.json"] = canonicalize_json_bytes(dict(inclusion_proof))
    if timestamp_metadata is not None:
        file_bytes["timestamp.json"] = canonicalize_json_bytes(dict(timestamp_metadata))
    if rfc3161_token is not None:
        file_bytes["rfc3161.tsr"] = bytes(rfc3161_token)

    sig = (attestation_obj.get("signature") or {})
    payload_hash = str(sig.get("signed_payload_hash") or "")
    attestation_hash = _normalize_hash(payload_hash)
    ordered = _ordered_paths(
        include_receipt=("receipt.json" in file_bytes),
        include_inclusion=("inclusion_proof.json" in file_bytes),
        include_timestamp=("timestamp.json" in file_bytes),
        include_tsr=("rfc3161.tsr" in file_bytes),
    )
    manifest = _manifest_payload(
        created_by=created_by,
        attestation_hash=attestation_hash,
        payload_hash=payload_hash,
        ordered_paths=ordered,
        file_bytes=file_bytes,
    )
    file_bytes[MANIFEST_PATH] = canonicalize_json_bytes(manifest)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_STORED) as zf:
        for path in ordered:
            zf.writestr(_zip_info(path), file_bytes[path])
    return buffer.getvalue()


def write_proofpack_v1_zip(
    *,
    out_path: str,
    attestation: Mapping[str, Any],
    signature_text: str,
    inputs: Mapping[str, Any],
    decision: Mapping[str, Any],
    created_by: str,
    receipt: Optional[Mapping[str, Any]] = None,
    inclusion_proof: Optional[Mapping[str, Any]] = None,
    timestamp_metadata: Optional[Mapping[str, Any]] = None,
    rfc3161_token: Optional[bytes] = None,
) -> Dict[str, Any]:
    payload = build_proofpack_v1_zip_bytes(
        attestation=attestation,
        signature_text=signature_text,
        inputs=inputs,
        decision=decision,
        created_by=created_by,
        receipt=receipt,
        inclusion_proof=inclusion_proof,
        timestamp_metadata=timestamp_metadata,
        rfc3161_token=rfc3161_token,
    )
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {
        "proofpack_version": PROOFPACK_VERSION,
        "out": str(path),
        "proofpack_hash": f"sha256:{_sha256_hex(payload)}",
        "size_bytes": len(payload),
    }


def _load_zip_entries(path: str) -> Tuple[List[str], Dict[str, bytes]]:
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        raise ValueError(f"proof pack not found: {path}")
    with zipfile.ZipFile(file_path, "r") as zf:
        names = zf.namelist()
        data = {name: zf.read(name) for name in names}
    return names, data


def _expected_order_from_names(names: Sequence[str]) -> List[str]:
    name_set = set(names)
    required = set(REQUIRED_BASE_ORDER) | {MANIFEST_PATH}
    missing = sorted(required - name_set)
    if missing:
        raise ValueError(f"proof pack missing required file(s): {missing}")
    unknown = sorted(name_set - (required | set(OPTIONAL_ORDER)))
    if unknown:
        raise ValueError(f"proof pack has unknown file(s): {unknown}")
    return _ordered_paths(
        include_receipt=("receipt.json" in name_set),
        include_inclusion=("inclusion_proof.json" in name_set),
        include_timestamp=("timestamp.json" in name_set),
        include_tsr=("rfc3161.tsr" in name_set),
    )


def verify_proofpack_v1_file(
    path: str,
    *,
    key_file: Optional[str] = None,
    tsa_ca_bundle: Optional[str] = None,
) -> Dict[str, Any]:
    names, data = _load_zip_entries(path)
    expected_order = _expected_order_from_names(names)
    if list(names) != expected_order:
        return {
            "ok": False,
            "error_code": "ORDER_INVALID",
            "details": {"expected_order": expected_order, "actual_order": names},
        }

    try:
        manifest = json.loads(data[MANIFEST_PATH].decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "error_code": "MANIFEST_INVALID", "details": {"error": str(exc)}}

    if str(manifest.get("proofpack_version") or "") != PROOFPACK_VERSION:
        return {
            "ok": False,
            "error_code": "VERSION_INVALID",
            "details": {"proofpack_version": manifest.get("proofpack_version")},
        }

    files = manifest.get("files")
    if not isinstance(files, list):
        return {"ok": False, "error_code": "MANIFEST_FILES_INVALID", "details": {}}
    expected_manifest_paths = [n for n in expected_order if n != MANIFEST_PATH]
    manifest_paths = [str(item.get("path") or "") for item in files if isinstance(item, dict)]
    if manifest_paths != expected_manifest_paths:
        return {
            "ok": False,
            "error_code": "MANIFEST_ORDER_INVALID",
            "details": {"expected": expected_manifest_paths, "actual": manifest_paths},
        }

    for item in files:
        if not isinstance(item, dict):
            return {"ok": False, "error_code": "MANIFEST_ENTRY_INVALID", "details": {"entry": item}}
        path_name = str(item.get("path") or "")
        payload = data.get(path_name)
        if payload is None:
            return {"ok": False, "error_code": "FILE_MISSING", "details": {"path": path_name}}
        expected_sha = _normalize_hash(str(item.get("sha256") or ""))
        actual_sha = _sha256_hex(payload)
        expected_size = int(item.get("size_bytes") or 0)
        if actual_sha != expected_sha:
            return {
                "ok": False,
                "error_code": "FILE_HASH_MISMATCH",
                "details": {"path": path_name, "expected": expected_sha, "actual": actual_sha},
            }
        if len(payload) != expected_size:
            return {
                "ok": False,
                "error_code": "FILE_SIZE_MISMATCH",
                "details": {"path": path_name, "expected": expected_size, "actual": len(payload)},
            }

    try:
        attestation_payload = json.loads(data["attestation.json"].decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "error_code": "ATTESTATION_INVALID", "details": {"error": str(exc)}}

    key_map = load_public_keys_map(key_file=key_file)
    attest_report = verify_attestation_payload(attestation_payload, public_keys_by_key_id=key_map)
    if not (
        attest_report.get("schema_valid")
        and attest_report.get("payload_hash_match")
        and attest_report.get("trusted_issuer")
        and attest_report.get("valid_signature")
    ):
        return {
            "ok": False,
            "error_code": "ATTESTATION_VERIFY_FAILED",
            "details": attest_report,
        }

    expected_sig = str(((attestation_payload.get("signature") or {}).get("signature_bytes")) or "")
    actual_sig = data["signature.txt"].decode("utf-8")
    if actual_sig != expected_sig:
        return {
            "ok": False,
            "error_code": "SIGNATURE_FILE_MISMATCH",
            "details": {"expected_len": len(expected_sig), "actual_len": len(actual_sig)},
        }

    has_timestamp_json = "timestamp.json" in data
    has_timestamp_token = "rfc3161.tsr" in data
    timestamp_verified: Optional[bool] = None
    if has_timestamp_json != has_timestamp_token:
        return {
            "ok": False,
            "error_code": "RFC3161_ARTIFACT_INVALID",
            "details": {
                "timestamp_json": has_timestamp_json,
                "timestamp_token": has_timestamp_token,
            },
        }
    if has_timestamp_json and has_timestamp_token:
        try:
            metadata = json.loads(data["timestamp.json"].decode("utf-8"))
        except Exception as exc:
            return {
                "ok": False,
                "error_code": "RFC3161_METADATA_INVALID",
                "details": {"error": str(exc)},
            }
        payload_hash = str(((attestation_payload.get("signature") or {}).get("signed_payload_hash")) or "")
        ok, error = verify_rfc3161_artifact(
            payload_hash=payload_hash,
            metadata=metadata,
            token_bytes=data["rfc3161.tsr"],
            ca_bundle_path=tsa_ca_bundle,
        )
        if not ok:
            return {
                "ok": False,
                "error_code": "RFC3161_VERIFY_FAILED",
                "details": {"error": error},
            }
        timestamp_verified = True

    inclusion_ok: Optional[bool] = None
    if "inclusion_proof.json" in data:
        try:
            proof_payload = json.loads(data["inclusion_proof.json"].decode("utf-8"))
        except Exception as exc:
            return {"ok": False, "error_code": "INCLUSION_PROOF_INVALID", "details": {"error": str(exc)}}
        inclusion_ok = bool(verify_inclusion_proof(proof_payload))
        if not inclusion_ok:
            return {"ok": False, "error_code": "INCLUSION_PROOF_VERIFY_FAILED", "details": {}}

    zip_bytes = Path(path).read_bytes()
    return {
        "ok": True,
        "proofpack_version": PROOFPACK_VERSION,
        "proofpack_hash": f"sha256:{_sha256_hex(zip_bytes)}",
        "file_order": names,
        "attestation": {
            "schema_valid": attest_report.get("schema_valid"),
            "payload_hash_match": attest_report.get("payload_hash_match"),
            "trusted_issuer": attest_report.get("trusted_issuer"),
            "valid_signature": attest_report.get("valid_signature"),
            "key_id": attest_report.get("key_id"),
        },
        "timestamp_verified": timestamp_verified,
        "inclusion_ok": inclusion_ok,
    }
