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
        policy_hash=policy_hash or "unknown-policy-hash",
        policy_bundle_hash=decision.policy_bundle_hash or "unknown-policy-bundle",
        policy_scope=[str(item) for item in resolved_scope],
        policy_resolution_hash=resolution_hash or policy_hash or "unknown-policy-hash",
        signals=input_snapshot,
        risk_score=None,
        decision=_status_to_attestation_decision(decision.release_status),
        reason_codes=reason_codes,
        timestamp=decision.timestamp.astimezone(timezone.utc).isoformat(),
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
    timestamp: Optional[str] = None,
    checkpoint_hashes: Optional[list[str]] = None,
    policy_scope: Optional[list[str]] = None,
    policy_resolution_hash: Optional[str] = None,
) -> DecisionBundle:
    issued_at = str(timestamp or "").strip() or datetime.now(timezone.utc).isoformat()
    seed = {
        "tenant_id": tenant_id,
        "repo": repo,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "policy_bundle_hash": policy_bundle_hash,
        "decision": decision,
        "reason_codes": reason_codes,
        "risk_score": risk_score,
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
        policy_hash=policy_hash,
        policy_bundle_hash=policy_bundle_hash,
        policy_scope=[str(item) for item in (policy_scope or [])],
        policy_resolution_hash=str(policy_resolution_hash or policy_hash or "").strip() or None,
        signals=signals or {},
        risk_score=float(risk_score),
        decision=_status_to_attestation_decision(decision),
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
    issued_at = str(bundle.timestamp or "").strip() or datetime.now(timezone.utc).isoformat()
    bundle_hash = _bundle_hash(bundle)

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
            policy_scope=list(bundle.policy_scope),
            policy_resolution_hash=bundle.policy_resolution_hash or bundle.policy_hash,
        ),
        decision=AttestationDecision(
            decision=bundle.decision,
            risk_score=bundle.risk_score,
            reason_codes=list(bundle.reason_codes),
        ),
        evidence=AttestationEvidence(
            signals_summary=dict(bundle.signals),
            dependency_provenance=dict(bundle.signals.get("dependency_provenance") or {}),
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
    payload_hash = hashlib.sha256(canonicalize_json_bytes(payload_wo_signature)).hexdigest()

    private_key = load_private_key_from_env()
    signature_b64 = sign_bytes(private_key, payload_hash)

    signed = dict(payload_wo_signature)
    signed["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_hash": f"sha256:{payload_hash}",
        "signature_bytes": signature_b64,
    }

    return ReleaseAttestation.model_validate(signed).model_dump(mode="json")
