from __future__ import annotations

import hashlib
import hmac
import json
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from releasegate.decision.hashing import (
    compute_decision_hash,
    compute_input_hash,
    compute_policy_hash_from_bindings,
    compute_replay_hash,
)
from releasegate.decision.types import Decision
from releasegate.replay.decision_replay import replay_decision
from releasegate.utils.canonical import canonical_json


CANONICALIZATION_VERSION = "releasegate-canonical-json-v1"
HASH_ALGORITHM = "sha256"
_PROOF_PACK_SIDELOAD_KEYS = {"in_toto_statement", "dsse_envelope", "dsse_error", "export_checksum", "proof_pack_id"}


class ProofPackFileError(RuntimeError):
    pass


@dataclass
class VerificationFailure(RuntimeError):
    code: str
    message: str
    details: Dict[str, Any]

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = str(raw).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _read_text(path: str) -> str:
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        raise ProofPackFileError(f"proof pack file not found: {path}")
    return file_path.read_text(encoding="utf-8")


def load_proof_pack_file(path: str) -> Dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        raise ProofPackFileError(f"proof pack file not found: {path}")

    sidecar_files = {
        "in_toto_statement": "in_toto_statement.json",
        "dsse_envelope": "dsse_envelope.json",
        "dsse_error": "dsse_error.json",
    }
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as zf:
                if "bundle.json" not in zf.namelist():
                    raise ProofPackFileError("zip proof pack missing bundle.json")
                raw = zf.read("bundle.json").decode("utf-8")
        else:
            raw = _read_text(path)
        payload = json.loads(raw)
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as zf:
                for key, name in sidecar_files.items():
                    if name not in zf.namelist():
                        continue
                    try:
                        sidecar = json.loads(zf.read(name).decode("utf-8"))
                    except Exception as exc:
                        raise ProofPackFileError(f"unable to parse {name}: {exc}") from exc
                    payload[key] = sidecar
    except ProofPackFileError:
        raise
    except Exception as exc:
        raise ProofPackFileError(f"unable to read proof pack: {exc}") from exc

    if not isinstance(payload, dict):
        raise ProofPackFileError("proof pack payload must be a JSON object")
    return payload


def _event_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "tenant_id": row.get("tenant_id"),
        "repo": row.get("repo"),
        "pr_number": row.get("pr_number"),
        "issue_key": row.get("issue_key"),
        "decision_id": row.get("decision_id"),
        "actor": row.get("actor"),
        "reason": row.get("reason"),
        "target_type": row.get("target_type"),
        "target_id": row.get("target_id"),
        "previous_hash": row.get("previous_hash"),
        "created_at": row.get("created_at"),
    }
    if row.get("idempotency_key") is not None:
        payload["idempotency_key"] = row.get("idempotency_key")
    if row.get("ttl_seconds") is not None:
        payload["ttl_seconds"] = row.get("ttl_seconds")
    if row.get("expires_at") is not None:
        payload["expires_at"] = row.get("expires_at")
    if row.get("requested_by") is not None:
        payload["requested_by"] = row.get("requested_by")
    if row.get("approved_by") is not None:
        payload["approved_by"] = row.get("approved_by")
    return payload


def _verify_ledger_chain(bundle: Dict[str, Any]) -> Dict[str, Any]:
    records = bundle.get("ledger_segment")
    integrity = (bundle.get("integrity") or {}).get("ledger") or {}
    expected_tip_hash = str(integrity.get("ledger_tip_hash") or "")
    expected_tip_id = str(integrity.get("ledger_record_id") or "")

    if not isinstance(records, list):
        raise VerificationFailure(
            code="LEDGER_CHAIN_INVALID",
            message="proof pack missing ledger_segment",
            details={"field": "ledger_segment"},
        )

    expected_prev = "0" * 64
    tip_hash = ""
    tip_id = ""
    for idx, row in enumerate(records):
        if not isinstance(row, dict):
            raise VerificationFailure(
                code="LEDGER_CHAIN_INVALID",
                message="ledger record is not an object",
                details={"index": idx},
            )
        previous_hash = str(row.get("previous_hash") or "")
        if previous_hash != expected_prev:
            raise VerificationFailure(
                code="LEDGER_CHAIN_INVALID",
                message="ledger previous_hash mismatch",
                details={"index": idx, "expected_previous_hash": expected_prev, "actual_previous_hash": previous_hash},
            )

        # Override chain hashes were historically produced with json.dumps(sort_keys=True)
        # (default separators). Match that exact encoding for backward-compatible verification.
        expected_hash = hashlib.sha256(
            json.dumps(_event_payload(row), sort_keys=True).encode("utf-8")
        ).hexdigest()
        event_hash = str(row.get("event_hash") or "")
        if expected_hash != event_hash:
            raise VerificationFailure(
                code="LEDGER_CHAIN_INVALID",
                message="ledger event hash mismatch",
                details={"index": idx, "expected_hash": expected_hash, "actual_hash": event_hash},
            )
        expected_prev = event_hash
        tip_hash = event_hash
        tip_id = str(row.get("override_id") or "")

    if tip_hash != expected_tip_hash:
        raise VerificationFailure(
            code="LEDGER_CHAIN_INVALID",
            message="ledger tip hash mismatch",
            details={"expected_tip_hash": expected_tip_hash, "actual_tip_hash": tip_hash},
        )

    if expected_tip_id and tip_id != expected_tip_id:
        raise VerificationFailure(
            code="LEDGER_CHAIN_INVALID",
            message="ledger tip record mismatch",
            details={"expected_tip_record": expected_tip_id, "actual_tip_record": tip_id},
        )

    return {
        "ok": True,
        "ledger_tip_hash": tip_hash,
        "ledger_record_id": tip_id,
        "record_count": len(records),
    }


def _load_key_from_file(path: str, tenant_id: str, key_id: str) -> Optional[str]:
    raw = Path(path).read_text(encoding="utf-8").strip()
    if not raw:
        return None
    if raw.startswith("{"):
        payload = json.loads(raw)
        if isinstance(payload, dict):
            if key_id and key_id in payload:
                return str(payload[key_id])
            tenant_payload = payload.get(tenant_id)
            if isinstance(tenant_payload, dict):
                if key_id and key_id in tenant_payload:
                    return str(tenant_payload[key_id])
                default_key = tenant_payload.get("default")
                if isinstance(default_key, str) and default_key.strip():
                    return default_key.strip()
            if key_id:
                nested = payload.get("keys")
                if isinstance(nested, dict) and key_id in nested:
                    return str(nested[key_id])
    return raw


def _resolve_trusted_signing_key(
    *,
    tenant_id: str,
    key_id: str,
    signing_key: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Tuple[str, str]:
    if signing_key:
        return signing_key, "cli"

    if key_file:
        resolved = _load_key_from_file(key_file, tenant_id=tenant_id, key_id=key_id)
        if resolved:
            return resolved, key_file

    default_json = Path.home() / ".releasegate" / "keys" / f"{tenant_id}.json"
    if default_json.exists():
        resolved = _load_key_from_file(str(default_json), tenant_id=tenant_id, key_id=key_id)
        if resolved:
            return resolved, str(default_json)

    default_key = Path.home() / ".releasegate" / "keys" / f"{tenant_id}.key"
    if default_key.exists():
        raw = default_key.read_text(encoding="utf-8").strip()
        if raw:
            return raw, str(default_key)

    env_key = (os.getenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY") or "").strip()
    if env_key:
        return env_key, "env:RELEASEGATE_CHECKPOINT_SIGNING_KEY"

    raise VerificationFailure(
        code="CHECKPOINT_SIGNATURE_INVALID",
        message="trusted checkpoint signing key not found",
        details={
            "tenant_id": tenant_id,
            "key_id": key_id,
            "checked_paths": [str(default_json), str(default_key)],
        },
    )


def _verify_checkpoint_signature(
    bundle: Dict[str, Any],
    *,
    signing_key: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Dict[str, Any]:
    checkpoint = bundle.get("checkpoint_snapshot")
    if not isinstance(checkpoint, dict):
        raise VerificationFailure(
            code="CHECKPOINT_SIGNATURE_INVALID",
            message="proof pack missing checkpoint_snapshot",
            details={"field": "checkpoint_snapshot"},
        )

    payload = checkpoint.get("payload")
    signature = checkpoint.get("signature") or {}
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise VerificationFailure(
            code="CHECKPOINT_SIGNATURE_INVALID",
            message="checkpoint snapshot missing payload/signature",
            details={"checkpoint_keys": list(checkpoint.keys())},
        )

    signature_value = str(signature.get("value") or "")
    key_id = str(signature.get("key_id") or "")
    tenant_id = str(bundle.get("tenant_id") or payload.get("tenant_id") or "")
    if not signature_value:
        raise VerificationFailure(
            code="CHECKPOINT_SIGNATURE_INVALID",
            message="checkpoint signature value is empty",
            details={},
        )

    integrity_signatures = (bundle.get("integrity") or {}).get("signatures") or {}
    expected_signature = str(integrity_signatures.get("checkpoint_signature") or "")
    expected_key_id = str(integrity_signatures.get("signing_key_id") or "")
    if expected_signature and expected_signature != signature_value:
        raise VerificationFailure(
            code="CHECKPOINT_SIGNATURE_INVALID",
            message="integrity checkpoint_signature does not match checkpoint snapshot",
            details={"expected": expected_signature, "actual": signature_value},
        )
    if expected_key_id and key_id and expected_key_id != key_id:
        raise VerificationFailure(
            code="CHECKPOINT_SIGNATURE_INVALID",
            message="integrity signing_key_id does not match checkpoint snapshot",
            details={"expected": expected_key_id, "actual": key_id},
        )

    trusted_key, key_source = _resolve_trusted_signing_key(
        tenant_id=tenant_id,
        key_id=key_id or expected_key_id,
        signing_key=signing_key,
        key_file=key_file,
    )
    expected = hmac.new(
        trusted_key.encode("utf-8"),
        canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature_value):
        raise VerificationFailure(
            code="CHECKPOINT_SIGNATURE_INVALID",
            message="checkpoint signature verification failed",
            details={"key_id": key_id, "key_source": key_source},
        )

    return {
        "ok": True,
        "key_id": key_id or expected_key_id,
        "key_source": key_source,
    }


def _verify_snapshot_hashes(bundle: Dict[str, Any]) -> Dict[str, Any]:
    integrity = bundle.get("integrity") or {}
    if not isinstance(integrity, dict):
        raise VerificationFailure(
            code="SNAPSHOT_HASH_MISMATCH",
            message="proof pack missing integrity section",
            details={"field": "integrity"},
        )

    canonicalization = str(integrity.get("canonicalization") or "")
    hash_alg = str(integrity.get("hash_alg") or "")
    if canonicalization != CANONICALIZATION_VERSION or hash_alg.lower() != HASH_ALGORITHM:
        raise VerificationFailure(
            code="SNAPSHOT_HASH_MISMATCH",
            message="integrity metadata mismatch",
            details={
                "expected": {
                    "canonicalization": CANONICALIZATION_VERSION,
                    "hash_alg": HASH_ALGORITHM,
                },
                "actual": {
                    "canonicalization": canonicalization,
                    "hash_alg": hash_alg,
                },
            },
        )

    input_snapshot = bundle.get("input_snapshot") or {}
    policy_snapshot = bundle.get("policy_snapshot") or []
    decision_snapshot = bundle.get("decision_snapshot") or {}

    computed = {
        "input_hash": compute_input_hash(input_snapshot),
        "policy_hash": compute_policy_hash_from_bindings(policy_snapshot),
        "decision_hash": compute_decision_hash(
            release_status=str(decision_snapshot.get("release_status") or "UNKNOWN"),
            reason_code=decision_snapshot.get("reason_code"),
            policy_bundle_hash=str(decision_snapshot.get("policy_bundle_hash") or ""),
            inputs_present=decision_snapshot.get("inputs_present") or {},
        ),
    }
    computed["replay_hash"] = compute_replay_hash(
        input_hash=computed["input_hash"],
        policy_hash=computed["policy_hash"],
        decision_hash=computed["decision_hash"],
    )

    mismatches = {}
    for field in ["input_hash", "policy_hash", "decision_hash", "replay_hash"]:
        expected = str(integrity.get(field) or "")
        actual = str(computed[field])
        if expected != actual:
            mismatches[field] = {"expected": expected, "actual": actual}

    if mismatches:
        raise VerificationFailure(
            code="SNAPSHOT_HASH_MISMATCH",
            message="snapshot hash verification failed",
            details={"mismatches": mismatches},
        )

    return {"ok": True, **computed}


def _verify_evidence_graph_hash(bundle: Dict[str, Any]) -> Dict[str, Any]:
    from releasegate.evidence.graph import compute_evidence_graph_hash

    integrity = bundle.get("integrity") or {}
    if not isinstance(integrity, dict):
        raise VerificationFailure(
            code="EVIDENCE_GRAPH_HASH_MISMATCH",
            message="proof pack missing integrity section",
            details={"field": "integrity"},
        )

    expected_graph_hash = str(integrity.get("graph_hash") or "")
    evidence_graph = bundle.get("evidence_graph")
    if not isinstance(evidence_graph, dict):
        if expected_graph_hash:
            raise VerificationFailure(
                code="EVIDENCE_GRAPH_HASH_MISMATCH",
                message="integrity has graph_hash but evidence_graph is missing",
                details={"field": "evidence_graph"},
            )
        return {"ok": True, "graph_hash": ""}

    computed_graph_hash = compute_evidence_graph_hash(evidence_graph)
    embedded_graph_hash = str(evidence_graph.get("graph_hash") or "")
    mismatches: Dict[str, Dict[str, str]] = {}
    if embedded_graph_hash and embedded_graph_hash != computed_graph_hash:
        mismatches["evidence_graph.graph_hash"] = {
            "expected": computed_graph_hash,
            "actual": embedded_graph_hash,
        }
    if expected_graph_hash and expected_graph_hash != computed_graph_hash:
        mismatches["integrity.graph_hash"] = {
            "expected": computed_graph_hash,
            "actual": expected_graph_hash,
        }
    if mismatches:
        raise VerificationFailure(
            code="EVIDENCE_GRAPH_HASH_MISMATCH",
            message="evidence graph hash verification failed",
            details={"mismatches": mismatches},
        )
    return {"ok": True, "graph_hash": computed_graph_hash}


def _verify_replay(bundle: Dict[str, Any]) -> Dict[str, Any]:
    decision_snapshot = bundle.get("decision_snapshot")
    if not isinstance(decision_snapshot, dict):
        raise VerificationFailure(
            code="REPLAY_MISMATCH",
            message="proof pack missing decision_snapshot",
            details={"field": "decision_snapshot"},
        )
    try:
        decision = Decision.model_validate(decision_snapshot)
        report = replay_decision(decision)
    except Exception as exc:
        raise VerificationFailure(
            code="REPLAY_MISMATCH",
            message=f"decision replay failed: {exc}",
            details={},
        ) from exc

    if not bool(report.get("matches_original")):
        raise VerificationFailure(
            code="REPLAY_MISMATCH",
            message="decision replay does not match original",
            details={
                "matches_original": report.get("matches_original"),
                "mismatch_reason": report.get("mismatch_reason"),
                "policy_hash_original": report.get("policy_hash_original"),
                "policy_hash_replay": report.get("policy_hash_replay"),
                "input_hash_original": report.get("input_hash_original"),
                "input_hash_replay": report.get("input_hash_replay"),
                "decision_hash_original": report.get("decision_hash_original"),
                "decision_hash_replay": report.get("decision_hash_replay"),
                "replay_hash_original": report.get("replay_hash_original"),
                "replay_hash_replay": report.get("replay_hash_replay"),
            },
        )

    return {
        "ok": True,
        "matches_original": True,
        "report": report,
    }


def _bundle_without_attestation_sidecars(bundle: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in bundle.items()
        if key not in _PROOF_PACK_SIDELOAD_KEYS
    }


def _verify_supply_chain_envelope(bundle: Dict[str, Any]) -> Dict[str, Any]:
    from releasegate.attestation.crypto import load_public_keys_map
    from releasegate.attestation.dsse import verify_dsse_signatures
    from releasegate.attestation.intoto import PREDICATE_TYPE_PROOF_PACK_V1, STATEMENT_TYPE_V1
    from releasegate.tenants.keys import KEY_STATUS_REVOKED, get_tenant_signing_public_keys_with_status
    from releasegate.utils.canonical import sha256_json

    statement = bundle.get("in_toto_statement")
    envelope = bundle.get("dsse_envelope")
    if not isinstance(statement, dict) and not isinstance(envelope, dict):
        return {"ok": True, "present": False, "signed": False}

    if isinstance(statement, dict):
        if str(statement.get("_type") or "") != STATEMENT_TYPE_V1:
            raise VerificationFailure(
                code="DSSE_STATEMENT_INVALID",
                message="in_toto_statement has invalid _type",
                details={"expected": STATEMENT_TYPE_V1, "actual": statement.get("_type")},
            )
        if str(statement.get("predicateType") or "") != PREDICATE_TYPE_PROOF_PACK_V1:
            raise VerificationFailure(
                code="DSSE_STATEMENT_INVALID",
                message="in_toto_statement has invalid predicateType",
                details={
                    "expected": PREDICATE_TYPE_PROOF_PACK_V1,
                    "actual": statement.get("predicateType"),
                },
            )

        subject = statement.get("subject")
        if not isinstance(subject, list) or not subject or not isinstance(subject[0], dict):
            raise VerificationFailure(
                code="DSSE_STATEMENT_INVALID",
                message="in_toto_statement subject is missing",
                details={},
            )
        subject_digest = str((subject[0].get("digest") or {}).get("sha256") or "").strip().lower()
        expected_digest = sha256_json(_bundle_without_attestation_sidecars(bundle))
        if not subject_digest or subject_digest != expected_digest:
            raise VerificationFailure(
                code="DSSE_STATEMENT_MISMATCH",
                message="in_toto_statement digest does not match proof bundle",
                details={"expected": expected_digest, "actual": subject_digest},
            )
        predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
        predicate_export_checksum = str(predicate.get("export_checksum") or "").strip().lower()
        if predicate_export_checksum and predicate_export_checksum != expected_digest:
            raise VerificationFailure(
                code="DSSE_STATEMENT_MISMATCH",
                message="in_toto_statement predicate export checksum mismatch",
                details={"expected": expected_digest, "actual": predicate_export_checksum},
            )

    if not isinstance(envelope, dict):
        return {"ok": True, "present": isinstance(statement, dict), "signed": False}

    tenant_id = str(bundle.get("tenant_id") or "").strip() or None
    revoked_key_map: Dict[str, str] = {}
    active_key_map: Dict[str, str] = {}
    if tenant_id:
        try:
            key_records = get_tenant_signing_public_keys_with_status(
                tenant_id=tenant_id,
                include_verify_only=True,
                include_revoked=True,
            )
        except Exception:
            key_records = {}
        for key_id, item in key_records.items():
            if not isinstance(item, dict):
                continue
            public_key = str(item.get("public_key") or "").strip()
            if not public_key:
                continue
            status = str(item.get("status") or "").strip().upper()
            if status == KEY_STATUS_REVOKED:
                revoked_key_map[str(key_id)] = public_key
            else:
                active_key_map[str(key_id)] = public_key
    key_map = active_key_map or load_public_keys_map(tenant_id=tenant_id)
    if not key_map and not revoked_key_map:
        raise VerificationFailure(
            code="DSSE_PUBLIC_KEYS_MISSING",
            message="no attestation public keys configured for DSSE verification",
            details={},
        )

    decoded, signatures, error = verify_dsse_signatures(envelope, key_map)
    revoked_signing_key_ids: list[str] = []
    if (error or not isinstance(decoded, dict)) and revoked_key_map:
        revoked_decoded, revoked_signatures, revoked_error = verify_dsse_signatures(envelope, revoked_key_map)
        if revoked_error:
            raise VerificationFailure(
                code="DSSE_SIGNATURE_INVALID",
                message=f"DSSE verification failed: {error or revoked_error}",
                details={"error_code": error or revoked_error},
            )
        if isinstance(revoked_decoded, dict):
            if _env_flag("RELEASEGATE_ALLOW_REVOKED_SIGNING_KEY_VERIFY", True):
                decoded = revoked_decoded
                signatures = revoked_signatures
                revoked_signing_key_ids = [
                    str(entry.get("keyid") or "")
                    for entry in revoked_signatures
                    if isinstance(entry, dict) and bool(entry.get("ok")) and str(entry.get("keyid") or "").strip()
                ]
            else:
                raise VerificationFailure(
                    code="DSSE_SIGNING_KEY_REVOKED",
                    message="DSSE signature verified only with revoked tenant signing key(s)",
                    details={"tenant_id": tenant_id},
                )
    if error:
        raise VerificationFailure(
            code="DSSE_SIGNATURE_INVALID",
            message=f"DSSE verification failed: {error}",
            details={"error_code": error},
        )
    if not isinstance(decoded, dict):
        raise VerificationFailure(
            code="DSSE_SIGNATURE_INVALID",
            message="DSSE payload is missing after signature verification",
            details={},
        )
    if isinstance(statement, dict) and decoded != statement:
        raise VerificationFailure(
            code="DSSE_STATEMENT_MISMATCH",
            message="DSSE payload does not match in_toto_statement",
            details={},
        )
    signing_key_ids = [
        str(entry.get("keyid") or "")
        for entry in signatures
        if isinstance(entry, dict) and bool(entry.get("ok"))
    ]
    return {
        "ok": True,
        "present": True,
        "signed": True,
        "signing_key_ids": sorted(key_id for key_id in signing_key_ids if key_id),
        "revoked_signing_key_ids": sorted(key_id for key_id in revoked_signing_key_ids if key_id),
    }


def verify_proof_pack_bundle(
    bundle: Dict[str, Any],
    *,
    signing_key: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ok": False,
        "schema_name": bundle.get("schema_name"),
        "schema_version": bundle.get("schema_version"),
        "tenant_id": bundle.get("tenant_id"),
        "ids": bundle.get("ids") or {},
        "checks": {},
        "ledger_ok": False,
        "signature_ok": False,
        "hashes_ok": False,
        "graph_ok": False,
        "replay_ok": False,
        "interop_ok": False,
        "matches_original": False,
        "failure_code": None,
        "error_code": None,
        "error_message": None,
    }
    try:
        result["checks"]["ledger"] = _verify_ledger_chain(bundle)
        result["ledger_ok"] = True
        result["checks"]["signature"] = _verify_checkpoint_signature(
            bundle,
            signing_key=signing_key,
            key_file=key_file,
        )
        result["signature_ok"] = True
        result["checks"]["hashes"] = _verify_snapshot_hashes(bundle)
        result["hashes_ok"] = True
        result["checks"]["graph"] = _verify_evidence_graph_hash(bundle)
        result["graph_ok"] = True
        result["checks"]["replay"] = _verify_replay(bundle)
        result["replay_ok"] = True
        result["matches_original"] = bool(result["checks"]["replay"].get("matches_original"))
        result["checks"]["interop"] = _verify_supply_chain_envelope(bundle)
        result["interop_ok"] = True
        result["ok"] = True
        return result
    except VerificationFailure as exc:
        result["failure_code"] = exc.code
        result["error_code"] = exc.code
        result["error_message"] = exc.message
        result["details"] = exc.details
        return result


def verify_proof_pack_file(
    path: str,
    *,
    signing_key: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Dict[str, Any]:
    bundle = load_proof_pack_file(path)
    return verify_proof_pack_bundle(bundle, signing_key=signing_key, key_file=key_file)


def format_verification_summary(report: Dict[str, Any]) -> str:
    checks = report.get("checks") or {}
    lines = []
    lines.append(f"ledger: {'OK' if checks.get('ledger', {}).get('ok') else 'FAIL'}")
    lines.append(
        "signature: "
        + ("OK" if checks.get("signature", {}).get("ok") else "FAIL")
        + (f" (key_id={checks.get('signature', {}).get('key_id')})" if checks.get("signature", {}).get("ok") else "")
    )
    lines.append(f"hashes: {'OK' if checks.get('hashes', {}).get('ok') else 'FAIL'}")
    lines.append(f"graph: {'OK' if checks.get('graph', {}).get('ok') else 'FAIL'}")
    replay = checks.get("replay", {})
    replay_suffix = ""
    if replay.get("ok"):
        replay_suffix = f" (matches_original={str(replay.get('matches_original')).lower()})"
    lines.append(f"replay: {'OK' if replay.get('ok') else 'FAIL'}{replay_suffix}")
    interop = checks.get("interop", {})
    if interop:
        lines.append(
            "interop: "
            + ("OK" if interop.get("ok") else "FAIL")
            + f" (signed={str(bool(interop.get('signed'))).lower()})"
        )
    if not report.get("ok"):
        lines.append(f"error_code: {report.get('error_code')}")
        lines.append(f"error_message: {report.get('error_message')}")
    return "\n".join(lines)
