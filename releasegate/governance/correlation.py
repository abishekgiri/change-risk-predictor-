from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from releasegate.correlation.enforcement import compute_release_correlation_id
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _normalize_text(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_record(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "correlation_id": row.get("correlation_id"),
        "tenant_id": row.get("tenant_id"),
        "jira_issue_key": row.get("jira_issue_key"),
        "pr_repo": row.get("pr_repo"),
        "pr_sha": row.get("pr_sha"),
        "deploy_id": row.get("deploy_id"),
        "incident_id": row.get("incident_id"),
        "environment": row.get("environment"),
        "change_ticket_key": row.get("change_ticket_key"),
        "decision_id": row.get("decision_id"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


@dataclass(frozen=True)
class CorrelationInput:
    jira_issue_key: Optional[str] = None
    pr_repo: Optional[str] = None
    pr_sha: Optional[str] = None
    deploy_id: Optional[str] = None
    incident_id: Optional[str] = None
    environment: Optional[str] = None
    change_ticket_key: Optional[str] = None
    decision_id: Optional[str] = None

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "CorrelationInput":
        return cls(
            jira_issue_key=_normalize_text(payload.get("jira_issue_key")),
            pr_repo=_normalize_text(payload.get("pr_repo")),
            pr_sha=_normalize_text(payload.get("pr_sha")),
            deploy_id=_normalize_text(payload.get("deploy_id")),
            incident_id=_normalize_text(payload.get("incident_id")),
            environment=_normalize_text(payload.get("environment")),
            change_ticket_key=_normalize_text(payload.get("change_ticket_key")),
            decision_id=_normalize_text(payload.get("decision_id")),
        )

    def to_update_map(self) -> Dict[str, Optional[str]]:
        return {
            "jira_issue_key": self.jira_issue_key,
            "pr_repo": self.pr_repo,
            "pr_sha": self.pr_sha,
            "deploy_id": self.deploy_id,
            "incident_id": self.incident_id,
            "environment": self.environment,
            "change_ticket_key": self.change_ticket_key,
            "decision_id": self.decision_id,
        }


def _derive_correlation_id(payload: CorrelationInput) -> str:
    if payload.jira_issue_key and payload.pr_repo and payload.pr_sha and payload.environment:
        return compute_release_correlation_id(
            issue_key=payload.jira_issue_key,
            repo=payload.pr_repo,
            commit_sha=payload.pr_sha,
            env=payload.environment,
        )
    return f"corr_{uuid.uuid4().hex[:24]}"


def _get_by_correlation_id(*, tenant_id: str, correlation_id: str) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, correlation_id, jira_issue_key, pr_repo, pr_sha, deploy_id, incident_id,
               environment, change_ticket_key, decision_id, created_at, updated_at
        FROM cross_system_correlations
        WHERE tenant_id = ? AND correlation_id = ?
        LIMIT 1
        """,
        (tenant_id, correlation_id),
    )
    if not row:
        return None
    return _row_to_record(row)


def _get_by_deploy_id(*, tenant_id: str, deploy_id: str) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, correlation_id, jira_issue_key, pr_repo, pr_sha, deploy_id, incident_id,
               environment, change_ticket_key, decision_id, created_at, updated_at
        FROM cross_system_correlations
        WHERE tenant_id = ? AND deploy_id = ?
        ORDER BY updated_at DESC
        LIMIT 1
        """,
        (tenant_id, deploy_id),
    )
    if not row:
        return None
    return _row_to_record(row)


def _get_by_incident_id(*, tenant_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, correlation_id, jira_issue_key, pr_repo, pr_sha, deploy_id, incident_id,
               environment, change_ticket_key, decision_id, created_at, updated_at
        FROM cross_system_correlations
        WHERE tenant_id = ? AND incident_id = ?
        ORDER BY updated_at DESC
        LIMIT 1
        """,
        (tenant_id, incident_id),
    )
    if not row:
        return None
    return _row_to_record(row)


def _merge_record(
    *,
    current: Dict[str, Any],
    incoming: CorrelationInput,
) -> tuple[Dict[str, Any], bool]:
    merged = dict(current)
    changed = False
    for key, value in incoming.to_update_map().items():
        if value is None:
            continue
        current_value = _normalize_text(merged.get(key))
        if current_value and current_value != value:
            raise ValueError(f"correlation field conflict for `{key}`: existing={current_value} incoming={value}")
        if not current_value:
            merged[key] = value
            changed = True
    return merged, changed


def create_correlation_record(
    *,
    tenant_id: Optional[str],
    correlation_id: Optional[str],
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized = CorrelationInput.from_dict(payload)
    environment = _normalize_text(normalized.environment)
    if not environment:
        raise ValueError("environment is required")

    resolved_correlation_id = _normalize_text(correlation_id) or _derive_correlation_id(normalized)
    existing = _get_by_correlation_id(
        tenant_id=effective_tenant,
        correlation_id=resolved_correlation_id,
    )
    if existing:
        merged, changed = _merge_record(current=existing, incoming=normalized)
        if not changed:
            return existing
        return update_correlation_record(
            tenant_id=effective_tenant,
            correlation_id=resolved_correlation_id,
            payload=merged,
        )

    now = _utc_now_iso()
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO cross_system_correlations (
            tenant_id, correlation_id, jira_issue_key, pr_repo, pr_sha, deploy_id, incident_id,
            environment, change_ticket_key, decision_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            resolved_correlation_id,
            normalized.jira_issue_key,
            normalized.pr_repo,
            normalized.pr_sha,
            normalized.deploy_id,
            normalized.incident_id,
            environment,
            normalized.change_ticket_key,
            normalized.decision_id,
            now,
            now,
        ),
    )
    created = _get_by_correlation_id(
        tenant_id=effective_tenant,
        correlation_id=resolved_correlation_id,
    )
    if not created:
        raise RuntimeError("failed to create correlation record")
    return created


def update_correlation_record(
    *,
    tenant_id: Optional[str],
    correlation_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    resolved_correlation_id = _normalize_text(correlation_id)
    if not resolved_correlation_id:
        raise ValueError("correlation_id is required")
    existing = _get_by_correlation_id(
        tenant_id=effective_tenant,
        correlation_id=resolved_correlation_id,
    )
    if not existing:
        raise ValueError("correlation record not found")

    incoming = CorrelationInput.from_dict(payload)
    merged, changed = _merge_record(current=existing, incoming=incoming)
    if not changed:
        return existing

    now = _utc_now_iso()
    storage = get_storage_backend()
    storage.execute(
        """
        UPDATE cross_system_correlations
        SET jira_issue_key = ?,
            pr_repo = ?,
            pr_sha = ?,
            deploy_id = ?,
            incident_id = ?,
            environment = ?,
            change_ticket_key = ?,
            decision_id = ?,
            updated_at = ?
        WHERE tenant_id = ? AND correlation_id = ?
        """,
        (
            _normalize_text(merged.get("jira_issue_key")),
            _normalize_text(merged.get("pr_repo")),
            _normalize_text(merged.get("pr_sha")),
            _normalize_text(merged.get("deploy_id")),
            _normalize_text(merged.get("incident_id")),
            _normalize_text(merged.get("environment")),
            _normalize_text(merged.get("change_ticket_key")),
            _normalize_text(merged.get("decision_id")),
            now,
            effective_tenant,
            resolved_correlation_id,
        ),
    )
    updated = _get_by_correlation_id(
        tenant_id=effective_tenant,
        correlation_id=resolved_correlation_id,
    )
    if not updated:
        raise RuntimeError("failed to update correlation record")
    return updated


def get_correlation_record(
    *,
    tenant_id: Optional[str],
    correlation_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    resolved = _normalize_text(correlation_id)
    if not resolved:
        return None
    return _get_by_correlation_id(
        tenant_id=effective_tenant,
        correlation_id=resolved,
    )


def find_correlation_record(
    *,
    tenant_id: Optional[str],
    deploy_id: Optional[str] = None,
    incident_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_deploy = _normalize_text(deploy_id)
    if normalized_deploy:
        found = _get_by_deploy_id(
            tenant_id=effective_tenant,
            deploy_id=normalized_deploy,
        )
        if found:
            return found
    normalized_incident = _normalize_text(incident_id)
    if normalized_incident:
        return _get_by_incident_id(
            tenant_id=effective_tenant,
            incident_id=normalized_incident,
        )
    return None
