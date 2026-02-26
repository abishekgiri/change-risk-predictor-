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


class ProofPackFileError(RuntimeError):
    pass


@dataclass
class VerificationFailure(RuntimeError):
    code: str
    message: str
    details: Dict[str, Any]

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _read_text(path: str) -> str:
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        raise ProofPackFileError(f"proof pack file not found: {path}")
    return file_path.read_text(encoding="utf-8")


def load_proof_pack_file(path: str) -> Dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        raise ProofPackFileError(f"proof pack file not found: {path}")

    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as zf:
                if "bundle.json" not in zf.namelist():
                    raise ProofPackFileError("zip proof pack missing bundle.json")
                raw = zf.read("bundle.json").decode("utf-8")
        else:
            raw = _read_text(path)
        payload = json.loads(raw)
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
    if not report.get("ok"):
        lines.append(f"error_code: {report.get('error_code')}")
        lines.append(f"error_message: {report.get('error_message')}")
    return "\n".join(lines)
