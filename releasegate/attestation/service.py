from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.attestation.canonicalize import canonicalize_json_bytes
from releasegate.attestation.crypto import current_key_id, load_private_key_from_env, sign_bytes
from releasegate.attestation.types import (
    AttestationDecision,
    AttestationEvidence,
    AttestationIssuer,
    AttestationPolicy,
    AttestationSignature,
    AttestationSubject,
    DecisionBundle,
    ReleaseAttestation,
)
from releasegate.decision.types import Decision
from releasegate.storage.base import resolve_tenant_id


def _decision_to_gate_value(release_status: str) -> str:
    return "BLOCK" if str(release_status).upper() == "BLOCKED" else "ALLOW"


def _extract_commit_sha(input_snapshot: Dict[str, Any], fallback_ref: Optional[str]) -> str:
    candidates = [
        input_snapshot.get("commit_sha"),
        input_snapshot.get("head_sha"),
        input_snapshot.get("sha"),
        (input_snapshot.get("github") or {}).get("head_sha") if isinstance(input_snapshot.get("github"), dict) else None,
        fallback_ref,
    ]
    for value in candidates:
        normalized = str(value or "").strip()
        if normalized:
            return normalized
    return "unknown"


def _extract_merge_sha(input_snapshot: Dict[str, Any]) -> Optional[str]:
    candidates = [
        input_snapshot.get("merge_sha"),
        (input_snapshot.get("github") or {}).get("merge_commit_sha") if isinstance(input_snapshot.get("github"), dict) else None,
    ]
    for value in candidates:
        normalized = str(value or "").strip()
        if normalized:
            return normalized
    return None


def _extract_risk_score(input_snapshot: Dict[str, Any]) -> Optional[float]:
    for key in ("risk_score", "severity", "score"):
        value = input_snapshot.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def _signals_summary(decision: Decision) -> Dict[str, Any]:
    snapshot = decision.input_snapshot or {}
    signals_obj = snapshot.get("signals")
    if isinstance(signals_obj, dict):
        return signals_obj

    summary: Dict[str, Any] = {
        "inputs_present": dict(decision.inputs_present or {}),
    }
    signal_map = snapshot.get("signal_map")
    if isinstance(signal_map, dict):
        summary["signal_map"] = signal_map

    metrics = snapshot.get("metrics")
    if isinstance(metrics, dict):
        summary["metrics"] = metrics

    for key in ("changed_files_count", "additions", "deletions", "total_churn"):
        if key in snapshot:
            summary.setdefault("metrics", {})
            if isinstance(summary["metrics"], dict):
                summary["metrics"][key] = snapshot.get(key)

    return summary


def _bundle_hash(bundle: DecisionBundle) -> str:
    canonical = canonicalize_json_bytes(bundle.model_dump(mode="json"))
    return hashlib.sha256(canonical).hexdigest()


def build_bundle_from_decision(
    decision: Decision,
    *,
    repo: str,
    pr_number: Optional[int],
    engine_version: str,
) -> DecisionBundle:
    policy_binding = (decision.policy_bindings or [None])[0]
    policy_version = "unknown"
    if policy_binding is not None:
        policy_version = str(getattr(policy_binding, "policy_version", "") or "unknown")

    reason_codes = [str(decision.reason_code)] if decision.reason_code else [str(decision.release_status)]
    checkpoint_hashes: list[str] = []
    if decision.replay_hash:
        checkpoint_hashes.append(decision.replay_hash)
    if decision.decision_hash and decision.decision_hash not in checkpoint_hashes:
        checkpoint_hashes.append(decision.decision_hash)

    return DecisionBundle(
        tenant_id=resolve_tenant_id(decision.tenant_id),
        decision_id=decision.decision_id,
        repo=repo,
        pr_number=pr_number,
        commit_sha=_extract_commit_sha(decision.input_snapshot or {}, decision.enforcement_targets.ref),
        merge_sha=_extract_merge_sha(decision.input_snapshot or {}),
        policy_version=policy_version,
        policy_hash=str(decision.policy_hash or ""),
        policy_bundle_hash=str(decision.policy_bundle_hash or ""),
        signals=_signals_summary(decision),
        risk_score=_extract_risk_score(decision.input_snapshot or {}),
        decision=_decision_to_gate_value(getattr(decision.release_status, "value", decision.release_status)),
        reason_codes=reason_codes,
        timestamp=decision.timestamp.astimezone(timezone.utc).isoformat(),
        engine_version=engine_version,
        checkpoint_hashes=checkpoint_hashes,
    )


def build_bundle_from_analysis_result(
    *,
    tenant_id: str,
    repo: str,
    pr_number: int,
    commit_sha: str,
    policy_hash: str,
    policy_version: str,
    policy_bundle_hash: str,
    risk_score: Optional[float],
    decision: str,
    reason_codes: list[str],
    signals: Dict[str, Any],
    engine_version: str,
    release_id: Optional[str] = None,
    build_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> DecisionBundle:
    stable_material = f"{tenant_id}:{repo}:{pr_number}:{commit_sha}:{policy_bundle_hash}:{decision}"
    decision_id = hashlib.sha256(stable_material.encode("utf-8")).hexdigest()[:32]
    return DecisionBundle(
        tenant_id=resolve_tenant_id(tenant_id),
        decision_id=decision_id,
        repo=repo,
        pr_number=pr_number,
        release_id=release_id,
        build_id=build_id,
        commit_sha=commit_sha or "unknown",
        policy_version=policy_version or "unknown",
        policy_hash=policy_hash,
        policy_bundle_hash=policy_bundle_hash,
        signals=signals or {},
        risk_score=risk_score,
        decision="BLOCK" if str(decision).upper() in {"BLOCK", "BLOCKED"} else "ALLOW",
        reason_codes=[r for r in reason_codes if r],
        timestamp=(timestamp or "1970-01-01T00:00:00Z"),
        engine_version=engine_version,
        checkpoint_hashes=[],
    )


def _attestation_payload_without_signature(
    bundle: DecisionBundle,
    *,
    key_id: str,
) -> Dict[str, Any]:
    environment = (os.getenv("RELEASEGATE_ENVIRONMENT") or "dev").strip().lower()
    org_id = (os.getenv("RELEASEGATE_ISSUER_ORG_ID") or bundle.tenant_id).strip()
    app_id = (os.getenv("RELEASEGATE_ISSUER_APP_ID") or "releasegate").strip()
    issued_at = str(bundle.timestamp or "").strip() or datetime.now(timezone.utc).isoformat()
    decision_bundle_hash = _bundle_hash(bundle)

    attestation = ReleaseAttestation(
        schema_version="1.0.0",
        attestation_type="releasegate.release_attestation",
        issued_at=issued_at,
        tenant_id=bundle.tenant_id,
        decision_id=bundle.decision_id,
        engine_version=bundle.engine_version,
        subject=AttestationSubject(
            repo=bundle.repo,
            commit_sha=bundle.commit_sha,
            merge_sha=bundle.merge_sha,
            pr_number=bundle.pr_number,
            build_id=bundle.build_id,
            release_id=bundle.release_id,
        ),
        policy=AttestationPolicy(
            policy_version=bundle.policy_version,
            policy_hash=bundle.policy_hash,
            policy_bundle_hash=bundle.policy_bundle_hash,
        ),
        decision=AttestationDecision(
            decision=bundle.decision,
            risk_score=bundle.risk_score,
            reason_codes=list(bundle.reason_codes),
        ),
        evidence=AttestationEvidence(
            signals_summary=bundle.signals,
            checkpoint_hashes=list(bundle.checkpoint_hashes),
            decision_bundle_hash=f"sha256:{decision_bundle_hash}",
        ),
        issuer=AttestationIssuer(
            org_id=org_id,
            app_id=app_id,
            environment=environment,
            key_id=key_id,
        ),
        signature=AttestationSignature(
            algorithm="ed25519",
            signed_payload_hash="",
            signature_bytes="",
        ),
    )
    payload = attestation.model_dump(mode="json")
    payload.pop("signature", None)
    return payload


def _payload_hash_hex(payload_without_signature: Dict[str, Any]) -> str:
    canonical = canonicalize_json_bytes(payload_without_signature)
    return hashlib.sha256(canonical).hexdigest()


def build_attestation_from_bundle(bundle: DecisionBundle | Dict[str, Any]) -> Dict[str, Any]:
    model = bundle if isinstance(bundle, DecisionBundle) else DecisionBundle.model_validate(bundle)
    key_id = current_key_id()
    payload_wo_sig = _attestation_payload_without_signature(model, key_id=key_id)
    payload_hash = _payload_hash_hex(payload_wo_sig)

    private_key = load_private_key_from_env()
    signature_b64 = sign_bytes(private_key, payload_hash)

    signed = dict(payload_wo_sig)
    signed["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_hash": f"sha256:{payload_hash}",
        "signature_bytes": signature_b64,
    }

    attestation = ReleaseAttestation.model_validate(signed)
    return attestation.model_dump(mode="json")
