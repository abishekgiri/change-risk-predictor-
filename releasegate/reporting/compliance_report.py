from __future__ import annotations

import os
from typing import Any, Dict, Iterable, Optional, Sequence


SCHEMA_VERSION = "compliance_report_v1"


def _unique_sorted(values: Iterable[str]) -> list[str]:
    out = []
    seen = set()
    for raw in values:
        v = str(raw).strip()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return sorted(out)


def normalize_verdict(control_result: str) -> str:
    value = str(control_result or "").strip().upper()
    if value == "PASS":
        return "PASS"
    if value == "WARN":
        return "WARN"
    if value in {"BLOCK", "FAIL"}:
        return "FAIL"
    # Fail closed for unknown values.
    return "FAIL"


def _normalize_enforcement_mode(raw: str) -> Optional[str]:
    value = str(raw or "").strip().lower()
    if not value:
        return None
    if value in {"monitor", "report_only", "report", "warn"}:
        return "monitor"
    if value in {"enforce", "block", "blocking"}:
        return "enforce"
    return None


def resolve_enforcement_mode(config: Optional[Dict[str, Any]] = None) -> str:
    """
    Resolve enforcement mode from env/config in a backwards-compatible way.

    Returns:
      "monitor" or "enforce"
    """
    env_raw = os.getenv("RELEASEGATE_ENFORCEMENT") or os.getenv("COMPLIANCEBOT_ENFORCEMENT") or ""
    env_mode = _normalize_enforcement_mode(env_raw)
    if env_mode:
        return env_mode

    cfg = config if isinstance(config, dict) else {}
    enforcement = cfg.get("enforcement")
    if isinstance(enforcement, dict):
        mode = _normalize_enforcement_mode(enforcement.get("mode"))
        if mode:
            return mode

    scoring = cfg.get("scoring")
    if isinstance(scoring, dict):
        mode = _normalize_enforcement_mode(scoring.get("enforcement"))
        if mode:
            return mode

    return "monitor"


def exit_code_for_verdict(enforcement_mode: str, verdict: str) -> int:
    mode = str(enforcement_mode or "").strip().lower() or "monitor"
    v = str(verdict or "").strip().upper()
    if mode == "enforce" and v == "FAIL":
        return 1
    return 0


def build_compliance_report(
    *,
    repo: str,
    pr_number: int,
    head_sha: Optional[str],
    base_sha: Optional[str],
    tenant_id: Optional[str],
    control_result: str,
    risk_score: Optional[float],
    risk_level: Optional[str],
    reasons: Sequence[str],
    reason_codes: Sequence[str],
    metrics: Optional[Dict[str, Any]] = None,
    dependency_provenance: Optional[Dict[str, Any]] = None,
    attached_issue_keys: Sequence[str] = (),
    policy_hash: Optional[str] = None,
    policy_resolution_hash: Optional[str] = None,
    policy_scope: Sequence[str] = (),
    enforcement_mode: str = "monitor",
    decision_id: Optional[str] = None,
    attestation_id: Optional[str] = None,
    signed_payload_hash: Optional[str] = None,
    dsse_path: Optional[str] = None,
    dsse_sigstore_bundle_path: Optional[str] = None,
    artifacts_sha256_path: Optional[str] = None,
    errors: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    control = str(control_result or "").strip().upper() or "FAIL"
    verdict = normalize_verdict(control)
    mode = str(enforcement_mode or "").strip().lower() or "monitor"
    if mode not in {"monitor", "enforce"}:
        mode = "monitor"

    m = metrics if isinstance(metrics, dict) else {}
    safe_metrics = {
        "changed_files_count": m.get("changed_files_count"),
        "additions": m.get("additions"),
        "deletions": m.get("deletions"),
        "total_churn": m.get("total_churn"),
    }

    report: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "verdict": verdict,
        "control_result": control,
        "decision": control,
        "decision_id": str(decision_id or "").strip() or "unknown",
        "attestation_id": str(attestation_id).strip() if attestation_id else None,
        "signed_payload_hash": str(signed_payload_hash).strip() if signed_payload_hash else None,
        "severity": float(risk_score) if risk_score is not None else None,
        "severity_level": str(risk_level).strip() if risk_level else None,
        "risk_score": float(risk_score) if risk_score is not None else None,
        "risk_level": str(risk_level).strip() if risk_level else None,
        "reasons": [str(r).strip() for r in (reasons or []) if str(r).strip()],
        "reason_codes": _unique_sorted(reason_codes or []),
        "metrics": safe_metrics,
        "dependency_provenance": dependency_provenance if isinstance(dependency_provenance, dict) else {},
        "attached_issue_keys": [str(k).strip() for k in (attached_issue_keys or []) if str(k).strip()],
        "policy_hash": str(policy_hash).strip() if policy_hash else None,
        "policy_resolution_hash": str(policy_resolution_hash).strip() if policy_resolution_hash else None,
        "policy_scope": [str(x).strip() for x in (policy_scope or []) if str(x).strip()],
        "enforcement_mode": mode,
        "dsse_path": str(dsse_path).strip() if dsse_path else None,
        "dsse_sigstore_bundle_path": str(dsse_sigstore_bundle_path).strip() if dsse_sigstore_bundle_path else None,
        "artifacts_sha256_path": str(artifacts_sha256_path).strip() if artifacts_sha256_path else None,
        "inputs": {
            "repo": str(repo).strip(),
            "pr_number": int(pr_number),
            "head_sha": str(head_sha).strip() if head_sha else None,
            "base_sha": str(base_sha).strip() if base_sha else None,
            "tenant_id": str(tenant_id).strip() if tenant_id else None,
        },
        "errors": _unique_sorted(errors or []),
    }
    return report

