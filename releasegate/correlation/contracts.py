from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from releasegate.audit.overrides import get_active_override
from releasegate.audit.reader import AuditReader
from releasegate.correlation.enforcement import compute_release_correlation_id
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


_PROD_ENVIRONMENTS = {"prod", "production"}
_APPROVED_TICKET_STATUSES = {"approved", "done", "closed", "implemented", "ready"}
_DEFAULT_RISK_FRESHNESS_MINUTES = 60


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _parse_json_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item or "").strip() for item in value if str(item or "").strip()]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [str(item or "").strip() for item in parsed if str(item or "").strip()]
    return []


def _parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = _normalize_text(value)
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = _normalize_lower(value)
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _extract_issue_key(payload: Dict[str, Any]) -> Optional[str]:
    targets = payload.get("enforcement_targets")
    if not isinstance(targets, dict):
        return None
    external = targets.get("external")
    if not isinstance(external, dict):
        return None
    jira_refs = external.get("jira")
    if not isinstance(jira_refs, list) or not jira_refs:
        return None
    value = _normalize_text(jira_refs[0])
    return value or None


def _extract_commit_sha(payload: Dict[str, Any]) -> Optional[str]:
    targets = payload.get("enforcement_targets")
    if not isinstance(targets, dict):
        return None
    value = _normalize_text(targets.get("ref"))
    return value or None


def _extract_repo(payload: Dict[str, Any], fallback: Optional[str]) -> Optional[str]:
    targets = payload.get("enforcement_targets")
    if isinstance(targets, dict):
        repo = _normalize_text(targets.get("repository"))
        if repo:
            return repo
    value = _normalize_text(fallback)
    return value or None


def _extract_artifact_digest(payload: Dict[str, Any]) -> Optional[str]:
    input_snapshot = payload.get("input_snapshot")
    if not isinstance(input_snapshot, dict):
        return None
    for key in ("artifact_digest", "artifact_hash", "artifact_sha256"):
        value = _normalize_text(input_snapshot.get(key))
        if value:
            return value
    return None


def _extract_risk_computed_at(payload: Dict[str, Any]) -> Optional[datetime]:
    input_snapshot = payload.get("input_snapshot")
    if not isinstance(input_snapshot, dict):
        return None
    risk_meta = input_snapshot.get("risk_meta")
    if isinstance(risk_meta, dict):
        dt = _parse_datetime(risk_meta.get("computed_at"))
        if dt is not None:
            return dt
    signal_map = input_snapshot.get("signal_map")
    if isinstance(signal_map, dict):
        risk = signal_map.get("risk")
        if isinstance(risk, dict):
            dt = _parse_datetime(risk.get("computed_at"))
            if dt is not None:
                return dt
    return None


def _find_decision_by_issue(
    *,
    tenant_id: str,
    issue_key: str,
    repo: Optional[str],
) -> Optional[Dict[str, Any]]:
    rows = AuditReader.search_decisions(
        tenant_id=tenant_id,
        jira_issue_key=issue_key,
        repo=repo,
        limit=50,
    )
    for row in rows:
        if _normalize_lower(row.get("release_status")) == "allowed":
            return row
    return rows[0] if rows else None


def _resolve_correlation_strict(*, environment: str, policy_overrides: Optional[Dict[str, Any]]) -> bool:
    overrides = policy_overrides or {}
    env_default = _as_bool(
        os.getenv("RELEASEGATE_CORRELATION_STRICT", os.getenv("CORRELATION_STRICT", "false")),
        default=False,
    )
    strict_enabled = _as_bool(overrides.get("correlation_strict"), default=env_default)
    if not strict_enabled:
        return False
    if _as_bool(overrides.get("correlation_strict_all_envs"), default=False):
        return True
    return _normalize_lower(environment) in _PROD_ENVIRONMENTS


def _resolve_risk_freshness_minutes(policy_overrides: Optional[Dict[str, Any]]) -> int:
    overrides = policy_overrides or {}
    value = overrides.get("risk_eval_freshness_minutes")
    if value is None:
        return _DEFAULT_RISK_FRESHNESS_MINUTES
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return _DEFAULT_RISK_FRESHNESS_MINUTES
    return max(1, minutes)


def _ticket_approved(*, jira_ticket_approved: Optional[bool], jira_ticket_status: Optional[str]) -> bool:
    if jira_ticket_approved is not None:
        return bool(jira_ticket_approved)
    status = _normalize_lower(jira_ticket_status)
    if not status:
        return False
    return status in _APPROVED_TICKET_STATUSES


def _dedupe_codes(codes: List[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for code in codes:
        normalized = _normalize_text(code)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _find_active_override(
    *,
    tenant_id: str,
    issue_key: Optional[str],
    repo: str,
    pr_number: Optional[int],
    at_time: datetime,
) -> Tuple[str, Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    issue = _normalize_text(issue_key)
    if issue:
        current = get_active_override(
            tenant_id=tenant_id,
            target_type="issue",
            target_id=issue,
            at_time=at_time,
        )
        if current is not None:
            return ("ACTIVE", str(current.get("override_id") or "").strip() or None, "issue", current)
    if pr_number is not None:
        current = get_active_override(
            tenant_id=tenant_id,
            target_type="pr",
            target_id=f"{repo}#{int(pr_number)}",
            at_time=at_time,
        )
        if current is not None:
            return ("ACTIVE", str(current.get("override_id") or "").strip() or None, "pr", current)
    current = get_active_override(
        tenant_id=tenant_id,
        target_type="repo",
        target_id=repo,
        at_time=at_time,
    )
    if current is not None:
        return ("ACTIVE", str(current.get("override_id") or "").strip() or None, "repo", current)
    return ("NONE", None, None, None)


def _fingerprint_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "decision_id",
        "jira_issue_id",
        "correlation_id",
        "environment",
        "service",
        "artifact_digest",
        "risk_eval_id",
        "risk_evaluated_at",
        "override_state_at_deploy",
        "override_id",
        "source",
        "contract_mode",
        "contract_verdict",
        "violation_codes_json",
        "reason",
    )
    normalized: Dict[str, Any] = {}
    for key in keys:
        value = payload.get(key)
        if key == "violation_codes_json":
            if isinstance(value, list):
                normalized[key] = json.dumps(
                    [str(item or "").strip() for item in value if str(item or "").strip()],
                    separators=(",", ":"),
                    sort_keys=False,
                )
            else:
                normalized[key] = _normalize_text(value)
            continue
        normalized[key] = _normalize_text(value)
    return normalized


def _record_deployment_link(
    *,
    tenant_id: str,
    deployment_event_id: str,
    decision_id: Optional[str],
    jira_issue_id: Optional[str],
    correlation_id: Optional[str],
    environment: str,
    service: str,
    artifact_digest: Optional[str],
    risk_eval_id: Optional[str],
    risk_evaluated_at: Optional[str],
    override_state_at_deploy: str,
    override_id: Optional[str],
    deployed_at: str,
    source: Optional[str],
    contract_mode: str,
    contract_verdict: str,
    violations: List[str],
    reason: str,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    now = _utc_now().isoformat()
    violation_codes_json = json.dumps(violations, separators=(",", ":"), sort_keys=False)
    payload = {
        "decision_id": decision_id or "",
        "jira_issue_id": jira_issue_id or "",
        "correlation_id": correlation_id or "",
        "environment": environment,
        "service": service,
        "artifact_digest": artifact_digest or "",
        "risk_eval_id": risk_eval_id or "",
        "risk_evaluated_at": risk_evaluated_at or "",
        "override_state_at_deploy": override_state_at_deploy,
        "override_id": override_id or "",
        "deployed_at": deployed_at,
        "source": source or "",
        "contract_mode": contract_mode,
        "contract_verdict": contract_verdict,
        "violation_codes_json": violation_codes_json,
        "reason": reason,
    }

    existing = storage.fetchone(
        """
        SELECT *
        FROM deployment_decision_links
        WHERE tenant_id = ? AND deployment_event_id = ?
        """,
        (tenant_id, deployment_event_id),
    )
    if existing:
        existing_payload = _fingerprint_payload(existing)
        if existing_payload != _fingerprint_payload(payload):
            raise ValueError("deployment_event_id already exists with different correlation payload")
        replayed = dict(existing)
        replayed["replayed"] = True
        replayed["violation_codes"] = _parse_json_list(existing.get("violation_codes_json"))
        return replayed

    storage.execute(
        """
        INSERT INTO deployment_decision_links (
            tenant_id,
            deployment_event_id,
            decision_id,
            jira_issue_id,
            correlation_id,
            environment,
            service,
            artifact_digest,
            risk_eval_id,
            risk_evaluated_at,
            override_state_at_deploy,
            override_id,
            deployed_at,
            source,
            contract_mode,
            contract_verdict,
            violation_codes_json,
            reason,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            deployment_event_id,
            decision_id,
            jira_issue_id,
            correlation_id,
            environment,
            service,
            artifact_digest,
            risk_eval_id,
            risk_evaluated_at,
            override_state_at_deploy,
            override_id,
            deployed_at,
            source,
            contract_mode,
            contract_verdict,
            violation_codes_json,
            reason,
            now,
        ),
    )
    return {
        "tenant_id": tenant_id,
        "deployment_event_id": deployment_event_id,
        **payload,
        "created_at": now,
        "replayed": False,
        "violation_codes": list(violations),
    }


def get_deployment_correlation_link(*, tenant_id: Optional[str], deployment_event_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT *
        FROM deployment_decision_links
        WHERE tenant_id = ? AND deployment_event_id = ?
        """,
        (effective_tenant, _normalize_text(deployment_event_id)),
    )
    if not row:
        return None
    return {
        **row,
        "violation_codes": _parse_json_list(row.get("violation_codes_json")),
    }


def evaluate_and_record_deployment_correlation(
    *,
    tenant_id: Optional[str],
    deployment_event_id: str,
    repo: str,
    environment: str,
    service: str,
    decision_id: Optional[str] = None,
    jira_issue_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    commit_sha: Optional[str] = None,
    artifact_digest: Optional[str] = None,
    risk_eval_id: Optional[str] = None,
    risk_evaluated_at: Optional[str] = None,
    deployed_at: Optional[str] = None,
    source: Optional[str] = None,
    jira_ticket_approved: Optional[bool] = None,
    jira_ticket_status: Optional[str] = None,
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_repo = _normalize_text(repo)
    normalized_env = _normalize_lower(environment)
    normalized_service = _normalize_text(service)
    normalized_event_id = _normalize_text(deployment_event_id)
    normalized_issue = _normalize_text(jira_issue_id) or None
    normalized_decision = _normalize_text(decision_id) or None
    normalized_commit = _normalize_text(commit_sha) or None
    normalized_artifact = _normalize_text(artifact_digest) or None
    normalized_corr = _normalize_text(correlation_id) or None
    normalized_source = _normalize_text(source) or None

    if not normalized_event_id:
        raise ValueError("deployment_event_id is required")
    if not normalized_repo:
        raise ValueError("repo is required")
    if not normalized_env:
        raise ValueError("environment is required")
    if not normalized_service:
        raise ValueError("service is required")

    overrides = policy_overrides or {}
    strict_mode = _resolve_correlation_strict(environment=normalized_env, policy_overrides=overrides)
    deployed_dt = _parse_datetime(deployed_at) or _utc_now()
    deployed_iso = deployed_dt.isoformat()
    violations: List[str] = []

    if normalized_env in _PROD_ENVIRONMENTS:
        if not normalized_issue:
            violations.append("MISSING_JIRA_TICKET")
        if not _ticket_approved(
            jira_ticket_approved=jira_ticket_approved,
            jira_ticket_status=jira_ticket_status,
        ):
            violations.append("JIRA_TICKET_NOT_APPROVED")
        if not normalized_decision:
            violations.append("MISSING_DECISION_ID")

    decision_row: Optional[Dict[str, Any]] = None
    if normalized_decision:
        decision_row = AuditReader.get_decision(normalized_decision, tenant_id=effective_tenant)
    elif normalized_issue:
        decision_row = _find_decision_by_issue(
            tenant_id=effective_tenant,
            issue_key=normalized_issue,
            repo=normalized_repo,
        )

    bound_issue: Optional[str] = normalized_issue
    bound_commit: Optional[str] = normalized_commit
    resolved_correlation: Optional[str] = normalized_corr
    resolved_decision_id: Optional[str] = normalized_decision
    resolved_artifact: Optional[str] = normalized_artifact
    resolved_risk_evaluated_at: Optional[datetime] = _parse_datetime(risk_evaluated_at)
    resolved_pr_number: Optional[int] = None

    if not decision_row:
        violations.append("DECISION_NOT_FOUND")
    else:
        resolved_decision_id = _normalize_text(decision_row.get("decision_id")) or resolved_decision_id
        resolved_pr_number = decision_row.get("pr_number")
        payload = _parse_json(decision_row.get("full_decision_json"))
        decision_issue = _extract_issue_key(payload)
        decision_repo = _extract_repo(payload, decision_row.get("repo"))
        decision_commit = _extract_commit_sha(payload)
        decision_artifact = _extract_artifact_digest(payload)
        decision_risk_evaluated_at = _extract_risk_computed_at(payload)

        if decision_issue and not bound_issue:
            bound_issue = decision_issue
        if decision_commit and not bound_commit:
            bound_commit = decision_commit
        if decision_artifact and not resolved_artifact:
            resolved_artifact = decision_artifact
        if decision_risk_evaluated_at and resolved_risk_evaluated_at is None:
            resolved_risk_evaluated_at = decision_risk_evaluated_at

        if _normalize_lower(decision_row.get("release_status")) != "allowed":
            violations.append("DECISION_NOT_APPROVED")
        if decision_repo and decision_repo != normalized_repo:
            violations.append("DEPLOY_REPO_MISMATCH")
        if normalized_issue and decision_issue and normalized_issue != decision_issue:
            violations.append("JIRA_ISSUE_MISMATCH")
        if normalized_commit and decision_commit and normalized_commit != decision_commit:
            violations.append("DEPLOY_COMMIT_MISMATCH")
        if normalized_artifact and decision_artifact and normalized_artifact != decision_artifact:
            violations.append("DEPLOY_ARTIFACT_MISMATCH")

        expected_corr = compute_release_correlation_id(
            issue_key=str(bound_issue or resolved_decision_id or ""),
            repo=normalized_repo,
            commit_sha=str(bound_commit or ""),
            env=normalized_env,
        )
        if normalized_corr:
            if normalized_corr != expected_corr:
                violations.append("CORRELATION_ID_MISMATCH")
            resolved_correlation = normalized_corr
        else:
            resolved_correlation = expected_corr

        freshness_minutes = _resolve_risk_freshness_minutes(overrides)
        if resolved_risk_evaluated_at is None:
            violations.append("RISK_EVAL_MISSING")
        else:
            age_seconds = (deployed_dt - resolved_risk_evaluated_at).total_seconds()
            if age_seconds > (float(freshness_minutes) * 60.0):
                violations.append("RISK_EVAL_STALE")

    override_state, override_id, _override_scope, _override_row = _find_active_override(
        tenant_id=effective_tenant,
        issue_key=bound_issue,
        repo=normalized_repo,
        pr_number=resolved_pr_number if isinstance(resolved_pr_number, int) else None,
        at_time=deployed_dt,
    )
    if override_state == "ACTIVE":
        violations.append("OVERRIDE_ACTIVE")

    unique_violations = _dedupe_codes(violations)
    has_violations = len(unique_violations) > 0
    contract_mode = "STRICT" if strict_mode else "AUDIT"

    if has_violations and strict_mode:
        allow = False
        status = "BLOCKED"
        reason_code = unique_violations[0]
        contract_verdict = "DENY"
        reason = "Deployment correlation contract failed in strict mode."
    elif has_violations:
        allow = True
        status = "ALLOWED"
        reason_code = "CORRELATION_CONTRACT_VIOLATION"
        contract_verdict = "VIOLATION"
        reason = "Deployment correlation contract violations recorded."
    else:
        allow = True
        status = "ALLOWED"
        reason_code = "CORRELATION_CONTRACT_OK"
        contract_verdict = "ALLOW"
        reason = "Deployment correlation contract checks passed."

    stored = _record_deployment_link(
        tenant_id=effective_tenant,
        deployment_event_id=normalized_event_id,
        decision_id=resolved_decision_id,
        jira_issue_id=bound_issue,
        correlation_id=resolved_correlation,
        environment=normalized_env,
        service=normalized_service,
        artifact_digest=resolved_artifact,
        risk_eval_id=_normalize_text(risk_eval_id) or None,
        risk_evaluated_at=resolved_risk_evaluated_at.isoformat() if resolved_risk_evaluated_at is not None else None,
        override_state_at_deploy=override_state,
        override_id=override_id,
        deployed_at=deployed_iso,
        source=normalized_source,
        contract_mode=contract_mode,
        contract_verdict=contract_verdict,
        violations=unique_violations,
        reason=reason,
    )

    return {
        "allow": allow,
        "status": status,
        "reason_code": reason_code,
        "reason": reason,
        "tenant_id": effective_tenant,
        "deployment_event_id": normalized_event_id,
        "decision_id": resolved_decision_id,
        "jira_issue_id": bound_issue,
        "correlation_id": resolved_correlation,
        "repo": normalized_repo,
        "environment": normalized_env,
        "service": normalized_service,
        "artifact_digest": resolved_artifact,
        "risk_eval_id": _normalize_text(risk_eval_id) or None,
        "risk_evaluated_at": resolved_risk_evaluated_at.isoformat() if resolved_risk_evaluated_at is not None else None,
        "deployed_at": deployed_iso,
        "contract_mode": contract_mode,
        "contract_verdict": contract_verdict,
        "violations": unique_violations,
        "override_active": override_state == "ACTIVE",
        "override_id": override_id,
        "strict": strict_mode,
        "replayed": bool(stored.get("replayed")),
    }
