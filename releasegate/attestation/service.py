from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from math import isfinite
from typing import Any, Dict, Optional

from releasegate.attestation.canonicalize import canonicalize_attestation_payload, canonicalize_json_bytes
from releasegate.attestation.crypto import current_key_id, load_private_key_from_env, sign_bytes
from releasegate.attestation.config import get_policy_schema_version
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
from releasegate.decision.types import Decision, DecisionType


def _status_to_attestation_decision(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text in {"BLOCK", "BLOCKED", "DENY", "DENIED", "ERROR"}:
        return "BLOCK"
    return "ALLOW"


def _extract_commit_sha(input_snapshot: Dict[str, Any], fallback_ref: Optional[str]) -> str:
    signal_map = input_snapshot.get("signal_map")
    if isinstance(signal_map, dict):
        for key in ("commit_sha", "head_sha", "sha"):
            value = signal_map.get(key)
            if value:
                return str(value)

    for key in ("commit_sha", "head_sha", "sha"):
        value = input_snapshot.get(key)
        if value:
            return str(value)

    if fallback_ref:
        return str(fallback_ref)
    return "unknown"


def _bundle_hash(bundle: DecisionBundle) -> str:
    canonical = canonicalize_json_bytes(bundle.model_dump(mode="json"))
    return hashlib.sha256(canonical).hexdigest()


def _normalize_utc_timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value or "").strip()
        if not raw:
            dt = datetime.now(timezone.utc)
        else:
            if raw.endswith("Z"):
                raw = f"{raw[:-1]}+00:00"
            dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalized_risk_score(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    score = float(value)
    if not isfinite(score):
        raise ValueError("risk_score must be finite")
    return round(score, 6)


def _risk_level(score: Optional[float], decision: str) -> str:
    if str(decision).upper() == "BLOCK":
        if score is None:
            return "HIGH"
        if score >= 0.66:
            return "HIGH"
    if score is not None:
        if score >= 0.66:
            return "HIGH"
        if score >= 0.33:
            return "MEDIUM"
    return "LOW"


def _signal_hash(signals: Dict[str, Any]) -> str:
    canonical = canonicalize_json_bytes(signals or {})
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _dependency_combined_hash(signals: Dict[str, Any]) -> Optional[str]:
    provenance = signals.get("dependency_provenance") if isinstance(signals, dict) else None
    if not isinstance(provenance, dict):
        return None
    value = str(provenance.get("combined_hash") or "").strip()
    if not value:
        return None
    if value.startswith("sha256:"):
        return value
    return f"sha256:{value}"


def _deterministic_decision_id(seed: Dict[str, Any]) -> str:
    digest = hashlib.sha256(canonicalize_json_bytes(seed)).hexdigest()
    return f"analysis-{digest[:24]}"


def build_bundle_from_decision(
    decision: Decision,
    repo: str,
    pr_number: Optional[int],
    engine_version: str,
) -> DecisionBundle:
    policy_binding = decision.policy_bindings[0] if decision.policy_bindings else None
    policy_version = str(policy_binding.policy_version if policy_binding else "1.0.0")
    policy_hash = str(decision.policy_hash or (policy_binding.policy_hash if policy_binding else ""))
    reason_codes = [str(decision.reason_code)] if decision.reason_code else []
    if not reason_codes and decision.release_status == DecisionType.BLOCKED:
        reason_codes = ["POLICY_BLOCKED"]

    input_snapshot = decision.input_snapshot if isinstance(decision.input_snapshot, dict) else {}
    resolved_scope = input_snapshot.get("policy_scope")
    if not isinstance(resolved_scope, list):
        resolved_scope = []
    resolution_hash = input_snapshot.get("policy_resolution_hash")
    if not isinstance(resolution_hash, str):
        resolution_hash = None

    return DecisionBundle(
        tenant_id=decision.tenant_id,
        decision_id=decision.decision_id,
        repo=repo,
        pr_number=pr_number,
        commit_sha=_extract_commit_sha(
            input_snapshot,
            decision.enforcement_targets.ref,
        ),
        policy_version=policy_version,
        policy_schema_version=get_policy_schema_version(),
        policy_hash=policy_hash or "unknown-policy-hash",
        policy_bundle_hash=decision.policy_bundle_hash or "unknown-policy-bundle",
        policy_scope=[str(item) for item in resolved_scope],
        policy_resolution_hash=resolution_hash or policy_hash or "unknown-policy-hash",
        signals=input_snapshot,
        risk_score=None,
        risk_level=_risk_level(None, _status_to_attestation_decision(decision.release_status)),
        override_flags=[],
        decision=_status_to_attestation_decision(decision.release_status),
        reason_codes=reason_codes,
        timestamp=_normalize_utc_timestamp(decision.timestamp),
        engine_version=engine_version,
        checkpoint_hashes=[],
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
    risk_score: float,
    decision: str,
    reason_codes: list[str],
    signals: Dict[str, Any],
    engine_version: str,
    policy_schema_version: Optional[str] = None,
    timestamp: Optional[str] = None,
    checkpoint_hashes: Optional[list[str]] = None,
    policy_scope: Optional[list[str]] = None,
    policy_resolution_hash: Optional[str] = None,
) -> DecisionBundle:
    issued_at = _normalize_utc_timestamp(timestamp)
    normalized_score = _normalized_risk_score(risk_score)
    normalized_decision = _status_to_attestation_decision(decision)
    override_flags_raw = signals.get("override_flags") if isinstance(signals, dict) else None
    override_flags = [str(item) for item in (override_flags_raw or []) if str(item).strip()]
    seed = {
        "tenant_id": tenant_id,
        "repo": repo,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "policy_bundle_hash": policy_bundle_hash,
        "decision": normalized_decision,
        "reason_codes": reason_codes,
        "risk_score": normalized_score,
        "signals": signals,
        "issued_at": issued_at,
    }
    decision_id = _deterministic_decision_id(seed)
    return DecisionBundle(
        tenant_id=tenant_id,
        decision_id=decision_id,
        repo=repo,
        pr_number=pr_number,
        commit_sha=commit_sha or "unknown",
        policy_version=policy_version,
        policy_schema_version=str(policy_schema_version or get_policy_schema_version()),
        policy_hash=policy_hash,
        policy_bundle_hash=policy_bundle_hash,
        policy_scope=[str(item) for item in (policy_scope or [])],
        policy_resolution_hash=str(policy_resolution_hash or policy_hash or "").strip() or None,
        signals=signals or {},
        risk_score=normalized_score,
        risk_level=_risk_level(normalized_score, normalized_decision),
        override_flags=override_flags,
        decision=normalized_decision,
        reason_codes=[str(code) for code in (reason_codes or [])],
        timestamp=issued_at,
        engine_version=engine_version,
        checkpoint_hashes=list(checkpoint_hashes or []),
    )


def _payload_without_signature(
    *,
    bundle: DecisionBundle,
    key_id: str,
) -> Dict[str, Any]:
    environment = (os.getenv("RELEASEGATE_ENVIRONMENT") or "dev").strip().lower()
    org_id = (os.getenv("RELEASEGATE_ISSUER_ORG_ID") or bundle.tenant_id).strip()
    app_id = (os.getenv("RELEASEGATE_ISSUER_APP_ID") or "releasegate").strip()
    issued_at = _normalize_utc_timestamp(bundle.timestamp)
    bundle_hash = _bundle_hash(bundle)
    signals_summary = dict(bundle.signals)
    dependency_provenance = dict(signals_summary.get("dependency_provenance") or {})
    dependency_combined_hash = _dependency_combined_hash(signals_summary)
    override_flags = [str(item) for item in (bundle.override_flags or []) if str(item).strip()]
    signal_hash = _signal_hash(signals_summary)
    normalized_score = _normalized_risk_score(bundle.risk_score)
    risk_level = bundle.risk_level or _risk_level(normalized_score, bundle.decision)

    attestation = ReleaseAttestation(
        schema_version="1.0.0",
        attestation_type="releasegate.release_attestation",
        issued_at=issued_at,
        policy_schema_version=str(bundle.policy_schema_version or get_policy_schema_version()),
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
            policy_scope=list(bundle.policy_scope),
            policy_resolution_hash=bundle.policy_resolution_hash or bundle.policy_hash,
        ),
        decision=AttestationDecision(
            decision=bundle.decision,
            risk_score=normalized_score,
            risk_level=risk_level,
            reason_codes=list(bundle.reason_codes),
        ),
        evidence=AttestationEvidence(
            signals_summary=signals_summary,
            signal_hash=signal_hash,
            dependency_provenance=dependency_provenance,
            dependency_combined_hash=dependency_combined_hash,
            override_flags=override_flags,
            checkpoint_hashes=list(bundle.checkpoint_hashes),
            decision_bundle_hash=f"sha256:{bundle_hash}",
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


def build_attestation_from_bundle(bundle: DecisionBundle | Dict[str, Any]) -> Dict[str, Any]:
    model = bundle if isinstance(bundle, DecisionBundle) else DecisionBundle.model_validate(bundle)
    key_id = current_key_id()
    payload_wo_signature = _payload_without_signature(bundle=model, key_id=key_id)
    payload_hash = hashlib.sha256(canonicalize_attestation_payload(payload_wo_signature)).hexdigest()

    private_key = load_private_key_from_env()
    signature_b64 = sign_bytes(private_key, payload_hash)

    signed = dict(payload_wo_signature)
    signed["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_hash": f"sha256:{payload_hash}",
        "signature_bytes": signature_b64,
    }

    return ReleaseAttestation.model_validate(signed).model_dump(mode="json")
