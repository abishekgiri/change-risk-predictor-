from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from releasegate.audit.reader import AuditReader
from releasegate.engine_core.evaluate import evaluate as evaluate_engine_core
from releasegate.engine_core.types import (
    Decision as CoreDecision,
    DecisionReason as CoreDecisionReason,
    EvaluationInput as CoreEvaluationInput,
    NormalizedContext as CoreNormalizedContext,
)
from releasegate.evidence.graph import (
    record_deployment_evidence,
    record_incident_evidence,
)
from releasegate.governance.signal_freshness import (
    evaluate_risk_signal_freshness,
    resolve_signal_freshness_policy,
)
from releasegate.governance.sod import evaluate_separation_of_duties
from releasegate.governance.strict_mode import apply_strict_fail_closed, resolve_strict_fail_closed
from releasegate.policy.releases import get_active_policy_release
from releasegate.storage.base import resolve_tenant_id
from releasegate.utils.canonical import sha256_json


def compute_release_correlation_id(
    *,
    issue_key: str,
    repo: str,
    commit_sha: str,
    env: str,
) -> str:
    payload = {
        "issue_key": str(issue_key or "").strip(),
        "repo": str(repo or "").strip().lower(),
        "commit_sha": str(commit_sha or "").strip().lower(),
        "env": str(env or "").strip().lower(),
    }
    return f"corr_{sha256_json(payload)}"


def _parse_decision_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = row.get("full_decision_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                return payload
        except Exception:
            return {}
    return {}


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
    value = str(jira_refs[0] or "").strip()
    return value or None


def _extract_commit_sha(payload: Dict[str, Any]) -> Optional[str]:
    targets = payload.get("enforcement_targets")
    if not isinstance(targets, dict):
        return None
    value = str(targets.get("ref") or "").strip()
    return value or None


def _extract_repo(payload: Dict[str, Any], fallback: Optional[str]) -> Optional[str]:
    targets = payload.get("enforcement_targets")
    if isinstance(targets, dict):
        repo = str(targets.get("repository") or "").strip()
        if repo:
            return repo
    value = str(fallback or "").strip()
    return value or None


def _extract_artifact_digest(payload: Dict[str, Any]) -> Optional[str]:
    input_snapshot = payload.get("input_snapshot")
    if not isinstance(input_snapshot, dict):
        return None
    for key in ("artifact_digest", "artifact_hash", "artifact_sha256"):
        value = str(input_snapshot.get(key) or "").strip()
        if value:
            return value
    return None


def _extract_risk_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    input_snapshot = payload.get("input_snapshot")
    if not isinstance(input_snapshot, dict):
        return {}
    risk_meta = input_snapshot.get("risk_meta")
    if isinstance(risk_meta, dict):
        return risk_meta
    signal_map = input_snapshot.get("signal_map")
    if not isinstance(signal_map, dict):
        return {}
    risk = signal_map.get("risk")
    if not isinstance(risk, dict):
        return {}
    normalized = {
        "risk_level": risk.get("level"),
        "releasegate_risk": risk.get("level"),
        "risk_score": risk.get("score"),
        "computed_at": risk.get("computed_at"),
        "signal_hash": risk.get("signal_hash"),
        "source": risk.get("source"),
    }
    return normalized


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
        if str(row.get("release_status") or "").upper() == "ALLOWED":
            return row
    return rows[0] if rows else None


@dataclass
class CorrelationResult:
    allow: bool
    status: str
    reason_code: str
    reason: str
    tenant_id: str
    decision_id: Optional[str]
    issue_key: Optional[str]
    correlation_id: Optional[str]
    repo: Optional[str]
    pr_number: Optional[int]
    commit_sha: Optional[str]
    env: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allow": self.allow,
            "status": self.status,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "tenant_id": self.tenant_id,
            "decision_id": self.decision_id,
            "issue_key": self.issue_key,
            "correlation_id": self.correlation_id,
            "repo": self.repo,
            "pr_number": self.pr_number,
            "commit_sha": self.commit_sha,
            "env": self.env,
        }


def _core_gate_decision(
    *,
    evaluation_kind: str,
    env: Optional[str],
    issue_key: Optional[str],
    transition_id: Optional[str] = None,
    repo: Optional[str],
    pr_number: Optional[int],
    actor_id: Optional[str] = None,
    reason_code: Optional[str] = None,
    reason_message: Optional[str] = None,
) -> CoreDecision:
    check_reasons = ()
    if reason_code:
        check_reasons = (
            CoreDecisionReason(
                code=str(reason_code),
                message=str(reason_message or reason_code),
                details={},
            ),
        )
    return evaluate_engine_core(
        CoreEvaluationInput(
            context=CoreNormalizedContext(
                evaluation_kind=evaluation_kind,
                environment=str(env or ""),
                issue_key=str(issue_key or ""),
                transition_id=str(transition_id or ""),
                repo=str(repo or ""),
                pr_number=pr_number,
                actor_id=str(actor_id or ""),
                evaluation_time="",
            ),
            check_reasons=check_reasons,
            success_status="ALLOWED",
            success_reason_code="CORRELATION_ALLOWED",
        )
    )


def _deny(
    *,
    tenant_id: str,
    reason_code: str,
    reason: str,
    decision_id: Optional[str],
    issue_key: Optional[str],
    correlation_id: Optional[str],
    repo: Optional[str],
    pr_number: Optional[int],
    commit_sha: Optional[str],
    env: Optional[str],
) -> CorrelationResult:
    core_decision = _core_gate_decision(
        evaluation_kind="correlation_gate",
        env=env,
        issue_key=issue_key,
        repo=repo,
        pr_number=pr_number,
        reason_code=reason_code,
        reason_message=reason,
    )
    return CorrelationResult(
        allow=core_decision.allow,
        status=core_decision.status,
        reason_code=core_decision.reason_code,
        reason=reason,
        tenant_id=tenant_id,
        decision_id=decision_id,
        issue_key=issue_key,
        correlation_id=correlation_id,
        repo=repo,
        pr_number=pr_number,
        commit_sha=commit_sha,
        env=env,
    )


def _allow(
    *,
    tenant_id: str,
    reason: str,
    decision_id: Optional[str],
    issue_key: Optional[str],
    correlation_id: Optional[str],
    repo: Optional[str],
    pr_number: Optional[int],
    commit_sha: Optional[str],
    env: Optional[str],
) -> CorrelationResult:
    core_decision = _core_gate_decision(
        evaluation_kind="correlation_gate",
        env=env,
        issue_key=issue_key,
        repo=repo,
        pr_number=pr_number,
        reason_code=None,
        reason_message=reason,
    )
    return CorrelationResult(
        allow=core_decision.allow,
        status=core_decision.status,
        reason_code=core_decision.reason_code,
        reason=reason,
        tenant_id=tenant_id,
        decision_id=decision_id,
        issue_key=issue_key,
        correlation_id=correlation_id,
        repo=repo,
        pr_number=pr_number,
        commit_sha=commit_sha,
        env=env,
    )


def evaluate_deploy_gate(
    *,
    tenant_id: Optional[str],
    decision_id: Optional[str],
    issue_key: Optional[str],
    correlation_id: Optional[str],
    deploy_id: Optional[str],
    repo: str,
    env: str,
    commit_sha: Optional[str],
    artifact_digest: Optional[str],
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_repo = str(repo or "").strip()
    normalized_env = str(env or "").strip().lower()
    normalized_issue = str(issue_key or "").strip() or None
    overrides = policy_overrides or {}
    strict_fail_closed = resolve_strict_fail_closed(
        policy_overrides=overrides,
        fallback=True,
    )
    allow_derive_correlation_id = bool(overrides.get("allow_derive_correlation_id", False))
    sod_violation = evaluate_separation_of_duties(
        actors={
            "actor": overrides.get("actor"),
            "pr_author": overrides.get("pr_author"),
            "override_requested_by": overrides.get("override_requested_by"),
            "override_approved_by": overrides.get("override_approved_by"),
        },
        config=overrides.get("separation_of_duties") if isinstance(overrides.get("separation_of_duties"), dict) else None,
    )
    if bool(overrides.get("override_used")) and sod_violation:
        return _deny(
            tenant_id=effective_tenant,
            reason_code=str(sod_violation.get("reason_code") or "SOD_CONFLICT"),
            reason=f"Separation-of-duties violation: {sod_violation.get('message')}",
            decision_id=decision_id,
            issue_key=normalized_issue,
            correlation_id=correlation_id,
            repo=normalized_repo or None,
            pr_number=None,
            commit_sha=commit_sha,
            env=normalized_env or None,
        ).to_dict()

    if not normalized_repo:
        return _deny(
            tenant_id=effective_tenant,
            reason_code="DEPLOY_REPO_REQUIRED",
            reason="Deployment repo is required.",
            decision_id=decision_id,
            issue_key=normalized_issue,
            correlation_id=correlation_id,
            repo=normalized_repo or None,
            pr_number=None,
            commit_sha=commit_sha,
            env=normalized_env or None,
        ).to_dict()
    if not normalized_env:
        return _deny(
            tenant_id=effective_tenant,
            reason_code="DEPLOY_ENV_REQUIRED",
            reason="Deployment target environment is required.",
            decision_id=decision_id,
            issue_key=normalized_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=None,
            commit_sha=commit_sha,
            env=None,
        ).to_dict()
    if not str(correlation_id or "").strip() and not allow_derive_correlation_id:
        return _deny(
            tenant_id=effective_tenant,
            reason_code="CORRELATION_ID_MISSING",
            reason="Deployment correlation_id is required by policy.",
            decision_id=decision_id,
            issue_key=normalized_issue,
            correlation_id=None,
            repo=normalized_repo,
            pr_number=None,
            commit_sha=commit_sha,
            env=normalized_env,
        ).to_dict()

    decision_row: Optional[Dict[str, Any]] = None
    if decision_id:
        decision_row = AuditReader.get_decision(str(decision_id), tenant_id=effective_tenant)
    elif normalized_issue:
        decision_row = _find_decision_by_issue(
            tenant_id=effective_tenant,
            issue_key=normalized_issue,
            repo=normalized_repo,
        )
    else:
        return _deny(
            tenant_id=effective_tenant,
            reason_code="DECISION_OR_ISSUE_REQUIRED",
            reason="Deploy gate requires decision_id or issue_key.",
            decision_id=None,
            issue_key=None,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=None,
            commit_sha=commit_sha,
            env=normalized_env,
        ).to_dict()

    if not decision_row:
        result = _deny(
            tenant_id=effective_tenant,
            reason_code="DECISION_NOT_FOUND",
            reason="No decision record found for deployment correlation.",
            decision_id=decision_id,
            issue_key=normalized_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=None,
            commit_sha=commit_sha,
            env=normalized_env,
        )
        return result.to_dict()

    payload = _parse_decision_payload(decision_row)
    bound_issue = normalized_issue or _extract_issue_key(payload)
    bound_repo = _extract_repo(payload, decision_row.get("repo"))
    bound_commit = _extract_commit_sha(payload)
    decision_artifact = _extract_artifact_digest(payload)
    risk_meta = _extract_risk_meta(payload)
    freshness_policy = resolve_signal_freshness_policy(
        policy_overrides=overrides.get("signals") if isinstance(overrides.get("signals"), dict) else None,
        strict_enabled=strict_fail_closed,
    )
    freshness = evaluate_risk_signal_freshness(
        risk_meta=risk_meta,
        policy=freshness_policy,
    )
    if freshness.get("stale") and freshness.get("should_block"):
        return _deny(
            tenant_id=effective_tenant,
            reason_code=str(freshness.get("reason_code") or "SIGNAL_STALE"),
            reason=f"Deployment blocked due to stale risk signal: {freshness.get('reason')}",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=bound_repo or normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=bound_commit,
            env=normalized_env,
        ).to_dict()

    if str(decision_row.get("release_status") or "").upper() != "ALLOWED":
        denied = _deny(
            tenant_id=effective_tenant,
            reason_code="DECISION_NOT_APPROVED",
            reason=f"Decision {decision_row.get('decision_id')} is not approved for deployment.",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=bound_repo or normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=bound_commit,
            env=normalized_env,
        )
        record_deployment_evidence(
            tenant_id=effective_tenant,
            deploy_ref=str(deploy_id or correlation_id or f"deploy:{normalized_repo}:{normalized_env}"),
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=str(correlation_id or ""),
            commit_sha=commit_sha,
            artifact_digest=artifact_digest,
            env=normalized_env,
            authorized=False,
        )
        return denied.to_dict()

    if bound_repo and bound_repo != normalized_repo:
        denied = _deny(
            tenant_id=effective_tenant,
            reason_code="DEPLOY_REPO_MISMATCH",
            reason=f"Deployment repo {normalized_repo} does not match approved repo {bound_repo}.",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=bound_commit,
            env=normalized_env,
        )
        return denied.to_dict()

    if commit_sha and bound_commit and str(commit_sha).strip() != str(bound_commit).strip():
        denied = _deny(
            tenant_id=effective_tenant,
            reason_code="DEPLOY_COMMIT_MISMATCH",
            reason=f"Deployment commit {commit_sha} does not match approved commit {bound_commit}.",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=commit_sha,
            env=normalized_env,
        )
        return denied.to_dict()

    if artifact_digest and decision_artifact and str(artifact_digest).strip() != str(decision_artifact).strip():
        denied = _deny(
            tenant_id=effective_tenant,
            reason_code="DEPLOY_ARTIFACT_MISMATCH",
            reason="Deployment artifact digest does not match approved decision artifact.",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=commit_sha or bound_commit,
            env=normalized_env,
        )
        return denied.to_dict()

    try:
        active_release = get_active_policy_release(
            tenant_id=effective_tenant,
            policy_id="releasegate.default",
            target_env=normalized_env,
        )
    except TimeoutError:
        strict_result = apply_strict_fail_closed(
            strict_enabled=strict_fail_closed,
            provider_timeout=True,
        )
        return _deny(
            tenant_id=effective_tenant,
            reason_code=(strict_result or {}).get("reason_code", "PROVIDER_TIMEOUT"),
            reason=(strict_result or {}).get("reason", "Policy release dependency timed out."),
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=commit_sha or bound_commit,
            env=normalized_env,
        ).to_dict()
    except Exception as exc:
        strict_result = apply_strict_fail_closed(
            strict_enabled=strict_fail_closed,
            provider_error="policy_release_lookup",
        )
        return _deny(
            tenant_id=effective_tenant,
            reason_code=(strict_result or {}).get("reason_code", "PROVIDER_ERROR"),
            reason=(strict_result or {}).get("reason", f"Policy release lookup failed: {exc}"),
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=commit_sha or bound_commit,
            env=normalized_env,
        ).to_dict()
    if not active_release:
        strict_result = apply_strict_fail_closed(
            strict_enabled=strict_fail_closed,
            policy_loaded=False,
        )
        denied = _deny(
            tenant_id=effective_tenant,
            reason_code=(strict_result or {}).get("reason_code", "POLICY_RELEASE_MISSING"),
            reason=(strict_result or {}).get(
                "reason",
                f"No active policy release found for environment {normalized_env}.",
            ),
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=commit_sha or bound_commit,
            env=normalized_env,
        )
        return denied.to_dict()

    resolved_correlation = correlation_id or compute_release_correlation_id(
        issue_key=str(bound_issue or decision_row.get("decision_id") or ""),
        repo=normalized_repo,
        commit_sha=str(commit_sha or bound_commit or ""),
        env=normalized_env,
    )
    expected_correlation = compute_release_correlation_id(
        issue_key=str(bound_issue or decision_row.get("decision_id") or ""),
        repo=normalized_repo,
        commit_sha=str(commit_sha or bound_commit or ""),
        env=normalized_env,
    )
    if correlation_id and correlation_id != expected_correlation:
        denied = _deny(
            tenant_id=effective_tenant,
            reason_code="CORRELATION_ID_MISMATCH",
            reason="Provided correlation_id does not match decision/deploy metadata.",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=normalized_repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=commit_sha or bound_commit,
            env=normalized_env,
        )
        return denied.to_dict()

    allowed = _allow(
        tenant_id=effective_tenant,
        reason="Deployment correlation checks passed.",
        decision_id=str(decision_row.get("decision_id") or ""),
        issue_key=bound_issue,
        correlation_id=resolved_correlation,
        repo=normalized_repo,
        pr_number=decision_row.get("pr_number"),
        commit_sha=commit_sha or bound_commit,
        env=normalized_env,
    )
    record_deployment_evidence(
        tenant_id=effective_tenant,
        deploy_ref=str(deploy_id or resolved_correlation),
        decision_id=str(decision_row.get("decision_id") or ""),
        issue_key=bound_issue,
        correlation_id=str(resolved_correlation),
        commit_sha=commit_sha or bound_commit,
        artifact_digest=artifact_digest or decision_artifact,
        env=normalized_env,
        authorized=True,
    )
    return allowed.to_dict()


def evaluate_incident_close_gate(
    *,
    tenant_id: Optional[str],
    incident_id: str,
    decision_id: Optional[str],
    issue_key: Optional[str],
    correlation_id: Optional[str],
    deploy_id: Optional[str],
    repo: Optional[str],
    env: Optional[str],
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_incident = str(incident_id or "").strip()
    overrides = policy_overrides or {}
    strict_fail_closed = resolve_strict_fail_closed(
        policy_overrides=overrides,
        fallback=True,
    )
    sod_violation = evaluate_separation_of_duties(
        actors={
            "actor": overrides.get("actor"),
            "pr_author": overrides.get("pr_author"),
            "override_requested_by": overrides.get("override_requested_by"),
            "override_approved_by": overrides.get("override_approved_by"),
        },
        config=overrides.get("separation_of_duties") if isinstance(overrides.get("separation_of_duties"), dict) else None,
    )
    if bool(overrides.get("override_used")) and sod_violation:
        return _deny(
            tenant_id=effective_tenant,
            reason_code=str(sod_violation.get("reason_code") or "SOD_CONFLICT"),
            reason=f"Separation-of-duties violation: {sod_violation.get('message')}",
            decision_id=decision_id,
            issue_key=issue_key,
            correlation_id=correlation_id,
            repo=repo,
            pr_number=None,
            commit_sha=None,
            env=env,
        ).to_dict()
    requires_deploy_link = bool(overrides.get("incident_close_requires_deploy_link", True))
    if not normalized_incident:
        return _deny(
            tenant_id=effective_tenant,
            reason_code="INCIDENT_ID_REQUIRED",
            reason="incident_id is required.",
            decision_id=decision_id,
            issue_key=issue_key,
            correlation_id=correlation_id,
            repo=repo,
            pr_number=None,
            commit_sha=None,
            env=env,
        ).to_dict()
    if requires_deploy_link and not str(deploy_id or "").strip() and not str(correlation_id or "").strip():
        return _deny(
            tenant_id=effective_tenant,
            reason_code="DEPLOY_LINK_REQUIRED",
            reason="Incident close requires deploy linkage (deploy_id or correlation_id).",
            decision_id=decision_id,
            issue_key=issue_key,
            correlation_id=correlation_id,
            repo=repo,
            pr_number=None,
            commit_sha=None,
            env=env,
        ).to_dict()

    decision_row: Optional[Dict[str, Any]] = None
    if decision_id:
        decision_row = AuditReader.get_decision(str(decision_id), tenant_id=effective_tenant)
    elif issue_key:
        decision_row = _find_decision_by_issue(
            tenant_id=effective_tenant,
            issue_key=str(issue_key),
            repo=repo,
        )
    if not decision_row:
        return _deny(
            tenant_id=effective_tenant,
            reason_code="DECISION_NOT_FOUND",
            reason="Incident closure requires an approved decision.",
            decision_id=decision_id,
            issue_key=issue_key,
            correlation_id=correlation_id,
            repo=repo,
            pr_number=None,
            commit_sha=None,
            env=env,
        ).to_dict()

    if str(decision_row.get("release_status") or "").upper() != "ALLOWED":
        denied = _deny(
            tenant_id=effective_tenant,
            reason_code="DECISION_NOT_APPROVED",
            reason="Incident closure blocked because decision is not approved.",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=issue_key,
            correlation_id=correlation_id,
            repo=repo or decision_row.get("repo"),
            pr_number=decision_row.get("pr_number"),
            commit_sha=None,
            env=env,
        )
        record_incident_evidence(
            tenant_id=effective_tenant,
            incident_ref=normalized_incident,
            decision_id=str(decision_row.get("decision_id") or ""),
            correlation_id=str(correlation_id or ""),
            deploy_ref=deploy_id,
            issue_key=str(issue_key or ""),
            allowed=False,
        )
        return denied.to_dict()

    payload = _parse_decision_payload(decision_row)
    risk_meta = _extract_risk_meta(payload)
    freshness_policy = resolve_signal_freshness_policy(
        policy_overrides=overrides.get("signals") if isinstance(overrides.get("signals"), dict) else None,
        strict_enabled=strict_fail_closed,
    )
    freshness = evaluate_risk_signal_freshness(
        risk_meta=risk_meta,
        policy=freshness_policy,
    )
    if freshness.get("stale") and freshness.get("should_block"):
        return _deny(
            tenant_id=effective_tenant,
            reason_code=str(freshness.get("reason_code") or "SIGNAL_STALE"),
            reason=f"Incident closure blocked due to stale risk signal: {freshness.get('reason')}",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=issue_key,
            correlation_id=correlation_id,
            repo=repo or decision_row.get("repo"),
            pr_number=decision_row.get("pr_number"),
            commit_sha=None,
            env=env,
        ).to_dict()

    bound_repo = _extract_repo(payload, decision_row.get("repo"))
    bound_issue = _extract_issue_key(payload) or str(issue_key or "").strip() or None
    bound_env = str(env or "prod").strip().lower()
    bound_commit = _extract_commit_sha(payload) or ""
    computed_correlation = compute_release_correlation_id(
        issue_key=str(bound_issue or decision_row.get("decision_id") or ""),
        repo=str(bound_repo or repo or ""),
        commit_sha=str(bound_commit),
        env=bound_env,
    )
    if correlation_id and correlation_id != computed_correlation:
        denied = _deny(
            tenant_id=effective_tenant,
            reason_code="CORRELATION_ID_MISMATCH",
            reason="Incident correlation_id does not match the approved release decision.",
            decision_id=str(decision_row.get("decision_id") or ""),
            issue_key=bound_issue,
            correlation_id=correlation_id,
            repo=bound_repo or repo,
            pr_number=decision_row.get("pr_number"),
            commit_sha=bound_commit or None,
            env=bound_env,
        )
        return denied.to_dict()

    if requires_deploy_link:
        from releasegate.evidence.graph import get_decision_evidence_graph

        try:
            graph = get_decision_evidence_graph(
                tenant_id=effective_tenant,
                decision_id=str(decision_row.get("decision_id") or ""),
                max_depth=2,
            ) or {"nodes": []}
        except TimeoutError:
            strict_result = apply_strict_fail_closed(
                strict_enabled=strict_fail_closed,
                provider_timeout=True,
            )
            return _deny(
                tenant_id=effective_tenant,
                reason_code=(strict_result or {}).get("reason_code", "PROVIDER_TIMEOUT"),
                reason=(strict_result or {}).get("reason", "Evidence graph lookup timed out."),
                decision_id=str(decision_row.get("decision_id") or ""),
                issue_key=bound_issue,
                correlation_id=correlation_id or computed_correlation,
                repo=bound_repo or repo,
                pr_number=decision_row.get("pr_number"),
                commit_sha=bound_commit or None,
                env=bound_env,
            ).to_dict()
        except Exception as exc:
            strict_result = apply_strict_fail_closed(
                strict_enabled=strict_fail_closed,
                provider_error="evidence_graph_lookup",
            )
            return _deny(
                tenant_id=effective_tenant,
                reason_code=(strict_result or {}).get("reason_code", "PROVIDER_ERROR"),
                reason=(strict_result or {}).get("reason", f"Evidence graph lookup failed: {exc}"),
                decision_id=str(decision_row.get("decision_id") or ""),
                issue_key=bound_issue,
                correlation_id=correlation_id or computed_correlation,
                repo=bound_repo or repo,
                pr_number=decision_row.get("pr_number"),
                commit_sha=bound_commit or None,
                env=bound_env,
            ).to_dict()
        deploy_nodes = [
            node
            for node in (graph.get("nodes") or [])
            if str(node.get("type") or "") == "DEPLOYMENT"
        ]
        target_ref = str(deploy_id or correlation_id or "").strip()
        deploy_match = None
        for node in deploy_nodes:
            ref = str(node.get("ref") or "").strip()
            payload = node.get("payload") or {}
            node_corr = str((payload or {}).get("correlation_id") or "").strip()
            if target_ref and (ref == target_ref or node_corr == target_ref):
                deploy_match = node
                break
        if deploy_match is None:
            return _deny(
                tenant_id=effective_tenant,
                reason_code="DEPLOY_NOT_FOUND_FOR_CORRELATION",
                reason="No deployment history found for incident correlation.",
                decision_id=str(decision_row.get("decision_id") or ""),
                issue_key=bound_issue,
                correlation_id=correlation_id or computed_correlation,
                repo=bound_repo or repo,
                pr_number=decision_row.get("pr_number"),
                commit_sha=bound_commit or None,
                env=bound_env,
            ).to_dict()

    allowed = _allow(
        tenant_id=effective_tenant,
        reason="Incident closure correlation checks passed.",
        decision_id=str(decision_row.get("decision_id") or ""),
        issue_key=bound_issue,
        correlation_id=correlation_id or computed_correlation,
        repo=bound_repo or repo,
        pr_number=decision_row.get("pr_number"),
        commit_sha=bound_commit or None,
        env=bound_env,
    )
    record_incident_evidence(
        tenant_id=effective_tenant,
        incident_ref=normalized_incident,
        decision_id=str(decision_row.get("decision_id") or ""),
        correlation_id=str(correlation_id or computed_correlation),
        deploy_ref=deploy_id,
        issue_key=bound_issue,
        allowed=True,
    )
    return allowed.to_dict()
