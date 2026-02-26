from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from releasegate.policy.analyzer import detect_transition_coverage
from releasegate.policy.inheritance import deep_merge_policies
from releasegate.policy.lint import lint_registry_policy
from releasegate.policy.models import ALLOWED_STATUS_TRANSITIONS, PolicyStatus
from releasegate.policy.store import append_registry_event
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


SCOPE_TYPES = {"org", "project", "workflow", "transition"}
POLICY_STATUSES = {status.value for status in PolicyStatus}
RESOLVE_STATUS_FILTERS = {"ACTIVE", "STAGED"}
ROLLOUT_SCOPES = {"project", "workflow", "transition"}
SCOPE_PRECEDENCE = ("org", "project", "workflow", "transition")
_SCOPE_RANK = {scope: idx for idx, scope in enumerate(SCOPE_PRECEDENCE)}
_MISSING = object()


class PolicyConflictError(ValueError):
    def __init__(self, *, code: str, scope_type: str, scope_id: str, stage: str, conflicts: Sequence[Dict[str, Any]]):
        self.code = str(code)
        self.scope_type = str(scope_type)
        self.scope_id = str(scope_id)
        self.stage = str(stage)
        self.conflicts = [dict(conflict) for conflict in conflicts]
        super().__init__(self.__str__())

    def __str__(self) -> str:
        payload = {
            "error_code": self.code,
            "scope_type": self.scope_type,
            "scope_id": self.scope_id,
            "stage": self.stage,
            "conflicts": self.conflicts,
        }
        return f"{self.code}: {canonical_json(payload)}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalise_scope_type(scope_type: str) -> str:
    value = str(scope_type or "").strip().lower()
    if value not in SCOPE_TYPES:
        raise ValueError(f"invalid scope_type: {scope_type}")
    return value


def _normalise_scope_id(scope_id: Optional[str]) -> str:
    value = str(scope_id or "").strip()
    if not value:
        raise ValueError("scope_id is required")
    return value


def _normalise_status(status: Optional[str]) -> str:
    value = str(status or "DRAFT").strip().upper()
    if value not in POLICY_STATUSES:
        raise ValueError(f"invalid policy status: {status}")
    return value


def _normalise_rollout_percentage(value: Optional[int]) -> int:
    if value is None:
        return 100
    percentage = int(value)
    if percentage < 0 or percentage > 100:
        raise ValueError("rollout_percentage must be between 0 and 100")
    return percentage


def _normalise_rollout_scope(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if not normalized:
        return None
    if normalized not in ROLLOUT_SCOPES:
        raise ValueError(f"invalid rollout_scope: {value}")
    return normalized


def _normalise_resolve_status(value: Optional[str]) -> str:
    normalized = str(value or "ACTIVE").strip().upper()
    if normalized not in RESOLVE_STATUS_FILTERS:
        raise ValueError(f"invalid resolve status filter: {value}")
    return normalized


def _normalise_policy_json(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("policy_json must be an object")
    return json.loads(canonical_json(payload))


def _policy_hash(policy_json: Dict[str, Any]) -> str:
    return f"sha256:{sha256_json(policy_json)}"


def _safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _normalise_roles(raw: Any) -> set[str]:
    if not isinstance(raw, list):
        return set()
    return {str(item).strip().lower() for item in raw if str(item).strip()}


def _assert_transition_allowed(*, from_status: str, to_status: str, action: str) -> None:
    normalized_from = _normalise_status(from_status)
    normalized_to = _normalise_status(to_status)
    if normalized_from == normalized_to:
        return
    from_enum = PolicyStatus(normalized_from)
    to_enum = PolicyStatus(normalized_to)
    allowed = ALLOWED_STATUS_TRANSITIONS.get(from_enum, frozenset())
    if to_enum not in allowed:
        raise ValueError(f"invalid policy lifecycle transition `{normalized_from}` -> `{normalized_to}` for {action}")
def _monotonic_conflicts(
    *,
    base_policy: Dict[str, Any],
    incoming_policy: Dict[str, Any],
    from_scope: str,
    to_scope: str,
) -> List[Dict[str, Any]]:
    """
    Enforce monotonic governance across policy hierarchy levels.
    Child scopes can add restrictions, but must not weaken inherited minimum guarantees.
    """
    incoming = json.loads(canonical_json(incoming_policy))
    conflicts: List[Dict[str, Any]] = []

    base_strict = bool(base_policy.get("strict_fail_closed", False))
    if base_strict and "strict_fail_closed" in incoming and not bool(incoming.get("strict_fail_closed")):
        conflicts.append(
            {
                "code": "POLICY_WEAKENING_STRICT_FAIL_CLOSED",
                "field": "strict_fail_closed",
                "from_scope": from_scope,
                "to_scope": to_scope,
                "parent_value": True,
                "child_value": incoming.get("strict_fail_closed"),
            }
        )

    base_required = _safe_int(base_policy.get("required_approvals"))
    child_required_raw = incoming.get("required_approvals", _MISSING)
    child_required = _safe_int(child_required_raw) if child_required_raw is not _MISSING else None
    if base_required is not None and child_required is not None and child_required < base_required:
        conflicts.append(
            {
                "code": "POLICY_WEAKENING_REQUIRED_APPROVALS",
                "field": "required_approvals",
                "from_scope": from_scope,
                "to_scope": to_scope,
                "parent_value": base_required,
                "child_value": child_required,
            }
        )

    base_approval_cfg = base_policy.get("approval_requirements")
    child_approval_cfg = incoming.get("approval_requirements")
    if isinstance(base_approval_cfg, dict) and isinstance(child_approval_cfg, dict):
        base_min = _safe_int(base_approval_cfg.get("min_approvals"))
        child_min_raw = child_approval_cfg.get("min_approvals", _MISSING)
        child_min = _safe_int(child_min_raw) if child_min_raw is not _MISSING else None
        if base_min is not None and child_min is not None and child_min < base_min:
            conflicts.append(
                {
                    "code": "POLICY_WEAKENING_MIN_APPROVALS",
                    "field": "approval_requirements.min_approvals",
                    "from_scope": from_scope,
                    "to_scope": to_scope,
                    "parent_value": base_min,
                    "child_value": child_min,
                }
            )

        base_roles = _normalise_roles(base_approval_cfg.get("required_roles"))
        child_roles_raw = child_approval_cfg.get("required_roles", _MISSING)
        if base_roles and child_roles_raw is not _MISSING:
            child_roles = _normalise_roles(child_roles_raw)
            if not child_roles:
                conflicts.append(
                    {
                        "code": "POLICY_WEAKENING_REQUIRED_ROLES",
                        "field": "approval_requirements.required_roles",
                        "from_scope": from_scope,
                        "to_scope": to_scope,
                        "parent_value": sorted(base_roles),
                        "child_value": [],
                    }
                )
            elif not base_roles.issubset(child_roles):
                conflicts.append(
                    {
                        "code": "POLICY_WEAKENING_REQUIRED_ROLES",
                        "field": "approval_requirements.required_roles",
                        "from_scope": from_scope,
                        "to_scope": to_scope,
                        "parent_value": sorted(base_roles),
                        "child_value": sorted(child_roles),
                    }
                )

    return conflicts


def _scope_context_for_policy(
    *,
    tenant_id: str,
    scope_type: str,
    scope_id: str,
    policy_json: Dict[str, Any],
) -> Dict[str, Optional[str]]:
    org_id = str(policy_json.get("org_id") or tenant_id).strip() or tenant_id
    project_id = str(policy_json.get("project_id") or "").strip() or None
    workflow_id = str(policy_json.get("workflow_id") or "").strip() or None
    transition_id = str(policy_json.get("transition_id") or "").strip() or None

    if scope_type == "project":
        project_id = scope_id
    elif scope_type == "workflow":
        workflow_id = scope_id
    elif scope_type == "transition":
        transition_id = scope_id

    return {
        "org_id": org_id,
        "project_id": project_id,
        "workflow_id": workflow_id,
        "transition_id": transition_id,
    }


def _scope_candidates_for_context(context: Dict[str, Optional[str]], scope_type: str, tenant_id: str) -> List[str]:
    if scope_type == "org":
        return [str(context.get("org_id") or tenant_id), tenant_id, "default", "*"]
    if scope_type == "project":
        project_id = str(context.get("project_id") or "").strip()
        return [project_id, "default", "*"] if project_id else ["default", "*"]
    if scope_type == "workflow":
        workflow_id = str(context.get("workflow_id") or "").strip()
        return [workflow_id, "default", "*"] if workflow_id else ["default", "*"]
    if scope_type == "transition":
        transition_id = str(context.get("transition_id") or "").strip()
        return [transition_id, "default", "*"] if transition_id else ["default", "*"]
    return []


def _resolve_parent_policy_baseline(
    *,
    tenant_id: str,
    scope_type: str,
    scope_id: str,
    policy_json: Dict[str, Any],
) -> Dict[str, Any]:
    if scope_type == "org":
        return {"effective_policy": {}, "parent_scopes": []}

    context = _scope_context_for_policy(
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_id=scope_id,
        policy_json=policy_json,
    )
    baseline: Dict[str, Any] = {}
    parent_scopes: List[str] = []
    current_rank = _SCOPE_RANK.get(scope_type, len(SCOPE_PRECEDENCE))
    for parent_scope in SCOPE_PRECEDENCE:
        if _SCOPE_RANK.get(parent_scope, 0) >= current_rank:
            break
        active = _latest_scope_policy(
            tenant_id=tenant_id,
            scope_type=parent_scope,
            scope_candidates=_scope_candidates_for_context(context, parent_scope, tenant_id),
            status="ACTIVE",
        )
        if not active:
            continue
        fragment = active.get("policy_json")
        if not isinstance(fragment, dict):
            continue
        baseline = deep_merge_policies(baseline, fragment)
        parent_scopes.append(parent_scope)
    return {"effective_policy": baseline, "parent_scopes": parent_scopes}


def _ensure_monotonic_policy(
    *,
    tenant_id: str,
    scope_type: str,
    scope_id: str,
    policy_json: Dict[str, Any],
    stage: str,
) -> None:
    parent = _resolve_parent_policy_baseline(
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_id=scope_id,
        policy_json=policy_json,
    )
    parent_policy = parent.get("effective_policy") if isinstance(parent.get("effective_policy"), dict) else {}
    if not parent_policy:
        return
    parent_scopes = parent.get("parent_scopes") if isinstance(parent.get("parent_scopes"), list) else []
    from_scope = ",".join(parent_scopes) if parent_scopes else "parent"
    conflicts = _monotonic_conflicts(
        base_policy=parent_policy,
        incoming_policy=policy_json,
        from_scope=from_scope,
        to_scope=scope_type,
    )
    if conflicts:
        raise PolicyConflictError(
            code="POLICY_MONOTONICITY_VIOLATION",
            scope_type=scope_type,
            scope_id=scope_id,
            stage=stage,
            conflicts=conflicts,
        )


def _parse_json_field(raw: Any, fallback: Any) -> Any:
    if raw is None:
        return fallback
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, type(fallback)):
                return parsed
            return fallback
        except Exception:
            return fallback
    return fallback


def _serialize_policy_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tenant_id": row.get("tenant_id"),
        "policy_id": row.get("policy_id"),
        "scope_type": row.get("scope_type"),
        "scope_id": row.get("scope_id"),
        "version": row.get("version"),
        "status": row.get("status"),
        "policy_hash": row.get("policy_hash"),
        "policy_json": _parse_json_field(row.get("policy_json"), {}),
        "lint_errors": _parse_json_field(row.get("lint_errors_json"), []),
        "lint_warnings": _parse_json_field(row.get("lint_warnings_json"), []),
        "rollout_percentage": row.get("rollout_percentage"),
        "rollout_scope": row.get("rollout_scope"),
        "created_at": row.get("created_at"),
        "created_by": row.get("created_by"),
        "activated_at": row.get("activated_at"),
        "activated_by": row.get("activated_by"),
        "archived_at": row.get("archived_at"),
        "supersedes_policy_id": row.get("supersedes_policy_id"),
    }


def _run_registry_lint(policy_json: Dict[str, Any]) -> Dict[str, Any]:
    report = lint_registry_policy(policy_json)
    coverage_issues = detect_transition_coverage(policy_json)
    if coverage_issues:
        merged = list(report.get("issues", []))
        existing_keys = {
            (
                str(issue.get("code")),
                canonical_json(issue.get("metadata", {})),
                str(issue.get("message")),
            )
            for issue in merged
        }
        for issue in coverage_issues:
            key = (
                str(issue.get("code")),
                canonical_json(issue.get("metadata", {})),
                str(issue.get("message")),
            )
            if key in existing_keys:
                continue
            merged.append(issue)
            existing_keys.add(key)
        report = dict(report)
        report["issues"] = merged
        report["error_count"] = sum(1 for issue in merged if issue.get("severity") == "ERROR")
        report["warning_count"] = sum(1 for issue in merged if issue.get("severity") == "WARNING")
        report["ok"] = report["error_count"] == 0
    return report


def _effective_policy_for_scope(
    *,
    tenant_id: str,
    scope_type: str,
    scope_id: str,
    policy_json: Dict[str, Any],
) -> Dict[str, Any]:
    parent = _resolve_parent_policy_baseline(
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_id=scope_id,
        policy_json=policy_json,
    )
    inherited = parent.get("effective_policy") if isinstance(parent.get("effective_policy"), dict) else {}
    return json.loads(canonical_json(deep_merge_policies(inherited, policy_json)))


def _validate_policy_ready_for_activation(*, tenant_id: str, policy: Dict[str, Any]) -> Dict[str, Any]:
    scope_type = str(policy.get("scope_type") or "")
    scope_id = str(policy.get("scope_id") or "")
    policy_json = policy.get("policy_json") if isinstance(policy.get("policy_json"), dict) else {}

    effective_candidate = _effective_policy_for_scope(
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_id=scope_id,
        policy_json=policy_json,
    )
    lint_report = _run_registry_lint(effective_candidate)
    lint_errors = [issue for issue in lint_report.get("issues", []) if issue.get("severity") == "ERROR"]
    if lint_errors:
        sample_codes = sorted({str(issue.get("code") or "") for issue in lint_errors if str(issue.get("code") or "")})
        raise ValueError(f"policy has lint errors and cannot be activated ({', '.join(sample_codes)})")

    scope_context = _scope_context_for_policy(
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_id=scope_id,
        policy_json=policy_json,
    )
    resolution = resolve_registry_policy(
        tenant_id=tenant_id,
        org_id=str(scope_context.get("org_id") or tenant_id),
        project_id=scope_context.get("project_id"),
        workflow_id=scope_context.get("workflow_id"),
        transition_id=scope_context.get("transition_id"),
        rollout_key=f"{scope_type}:{scope_id}",
        status_filter="STAGED",
    )
    conflicts = resolution.get("resolution_conflicts") if isinstance(resolution.get("resolution_conflicts"), list) else []
    if conflicts:
        raise PolicyConflictError(
            code="POLICY_RESOLUTION_CONFLICT",
            scope_type=scope_type,
            scope_id=scope_id,
            stage="activate",
            conflicts=conflicts,
        )
    return {
        "effective_policy_hash": str(resolution.get("effective_policy_hash") or ""),
        "component_policy_ids": list(resolution.get("component_policy_ids") or []),
    }


def _next_scope_version(*, tenant_id: str, scope_type: str, scope_id: str) -> int:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT COALESCE(MAX(version), 0) AS current
        FROM policy_registry_entries
        WHERE tenant_id = ? AND scope_type = ? AND scope_id = ?
        """,
        (tenant_id, scope_type, scope_id),
    )
    current = int((row or {}).get("current") or 0)
    return current + 1


def get_registry_policy(*, tenant_id: Optional[str], policy_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, policy_id, scope_type, scope_id, version, status,
               policy_hash, policy_json, lint_errors_json, lint_warnings_json,
               rollout_percentage, rollout_scope,
               created_at, created_by, activated_at, activated_by, archived_at, supersedes_policy_id
        FROM policy_registry_entries
        WHERE tenant_id = ? AND policy_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(policy_id)),
    )
    if not row:
        return None
    return _serialize_policy_row(row)


def list_registry_policies(
    *,
    tenant_id: Optional[str],
    scope_type: Optional[str] = None,
    scope_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    query = [
        """
        SELECT tenant_id, policy_id, scope_type, scope_id, version, status,
               policy_hash, policy_json, lint_errors_json, lint_warnings_json,
               rollout_percentage, rollout_scope,
               created_at, created_by, activated_at, activated_by, archived_at, supersedes_policy_id
        FROM policy_registry_entries
        WHERE tenant_id = ?
        """
    ]
    params: List[Any] = [effective_tenant]
    if scope_type:
        query.append("AND scope_type = ?")
        params.append(_normalise_scope_type(scope_type))
    if scope_id:
        query.append("AND scope_id = ?")
        params.append(_normalise_scope_id(scope_id))
    if status:
        query.append("AND status = ?")
        params.append(_normalise_status(status))
    query.append("ORDER BY created_at DESC")
    query.append("LIMIT ?")
    params.append(max(1, min(int(limit), 500)))

    rows = storage.fetchall("\n".join(query), params)
    return [_serialize_policy_row(row) for row in rows]


def create_registry_policy(
    *,
    tenant_id: Optional[str],
    scope_type: str,
    scope_id: str,
    policy_json: Dict[str, Any],
    created_by: Optional[str],
    status: str = "DRAFT",
    rollout_percentage: Optional[int] = 100,
    rollout_scope: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_scope_type = _normalise_scope_type(scope_type)
    normalized_scope_id = _normalise_scope_id(scope_id)
    normalized_status = _normalise_status(status)
    if normalized_status == PolicyStatus.DEPRECATED.value:
        normalized_status = PolicyStatus.ARCHIVED.value
    normalized_rollout_percentage = _normalise_rollout_percentage(rollout_percentage)
    normalized_rollout_scope = _normalise_rollout_scope(rollout_scope)
    normalized_policy_json = _normalise_policy_json(policy_json)
    policy_hash = _policy_hash(normalized_policy_json)
    _ensure_monotonic_policy(
        tenant_id=effective_tenant,
        scope_type=normalized_scope_type,
        scope_id=normalized_scope_id,
        policy_json=normalized_policy_json,
        stage="create",
    )

    lint_report = _run_registry_lint(
        _effective_policy_for_scope(
            tenant_id=effective_tenant,
            scope_type=normalized_scope_type,
            scope_id=normalized_scope_id,
            policy_json=normalized_policy_json,
        )
    )
    lint_errors = [issue for issue in lint_report.get("issues", []) if issue.get("severity") == "ERROR"]
    lint_warnings = [issue for issue in lint_report.get("issues", []) if issue.get("severity") == "WARNING"]

    storage = get_storage_backend()
    policy_id = str(uuid.uuid4())
    created_at = _utc_now()
    version = _next_scope_version(
        tenant_id=effective_tenant,
        scope_type=normalized_scope_type,
        scope_id=normalized_scope_id,
    )

    with storage.transaction() as tx:
        tx.execute(
            """
            INSERT INTO policy_registry_entries (
                tenant_id, policy_id, scope_type, scope_id, version, status,
                policy_json, policy_hash, lint_errors_json, lint_warnings_json,
                rollout_percentage, rollout_scope,
                created_at, created_by, archived_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                policy_id,
                normalized_scope_type,
                normalized_scope_id,
                version,
                "DRAFT",
                canonical_json(normalized_policy_json),
                policy_hash,
                canonical_json(lint_errors),
                canonical_json(lint_warnings),
                normalized_rollout_percentage,
                normalized_rollout_scope,
                created_at,
                str(created_by or "") or None,
                None,
            ),
        )
    append_registry_event(
        tenant_id=effective_tenant,
        policy_id=policy_id,
        event_type="POLICY_CREATED",
        actor_id=created_by,
        metadata={
            "scope_type": normalized_scope_type,
            "scope_id": normalized_scope_id,
            "version": version,
            "requested_status": normalized_status,
            "policy_hash": policy_hash,
            "lint_error_count": len(lint_errors),
            "lint_warning_count": len(lint_warnings),
        },
    )

    if normalized_status == PolicyStatus.STAGED.value:
        return stage_registry_policy(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            actor_id=created_by,
        )

    if normalized_status == PolicyStatus.ACTIVE.value:
        stage_registry_policy(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            actor_id=created_by,
        )
        return activate_registry_policy(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            actor_id=created_by,
        )

    if normalized_status == PolicyStatus.ARCHIVED.value:
        return archive_registry_policy(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            actor_id=created_by,
        )

    return get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id) or {
        "tenant_id": effective_tenant,
        "policy_id": policy_id,
        "scope_type": normalized_scope_type,
        "scope_id": normalized_scope_id,
        "version": version,
        "status": PolicyStatus.DRAFT.value,
        "policy_hash": policy_hash,
        "policy_json": normalized_policy_json,
        "lint_errors": lint_errors,
        "lint_warnings": lint_warnings,
        "rollout_percentage": normalized_rollout_percentage,
        "rollout_scope": normalized_rollout_scope,
            "created_at": created_at,
            "created_by": str(created_by or "") or None,
            "activated_at": None,
            "activated_by": None,
            "archived_at": None,
        "supersedes_policy_id": None,
    }


def stage_registry_policy(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    actor_id: Optional[str],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    policy = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not policy:
        raise ValueError("policy not found")

    current_status = _normalise_status(policy.get("status"))
    if current_status == PolicyStatus.STAGED.value:
        return policy
    _assert_transition_allowed(from_status=current_status, to_status=PolicyStatus.STAGED.value, action="stage")

    _ensure_monotonic_policy(
        tenant_id=effective_tenant,
        scope_type=str(policy.get("scope_type") or ""),
        scope_id=str(policy.get("scope_id") or ""),
        policy_json=policy.get("policy_json") if isinstance(policy.get("policy_json"), dict) else {},
        stage="stage",
    )

    storage = get_storage_backend()
    storage.execute(
        """
        UPDATE policy_registry_entries
        SET status = 'STAGED', archived_at = NULL
        WHERE tenant_id = ? AND policy_id = ?
        """,
        (effective_tenant, str(policy_id)),
    )
    append_registry_event(
        tenant_id=effective_tenant,
        policy_id=str(policy_id),
        event_type="POLICY_STAGED",
        actor_id=actor_id,
        metadata={
            "scope_type": policy.get("scope_type"),
            "scope_id": policy.get("scope_id"),
            "policy_hash": policy.get("policy_hash"),
            "from_status": current_status,
            "to_status": PolicyStatus.STAGED.value,
        },
    )
    staged = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not staged:
        raise ValueError("policy staging failed")
    return staged


def _latest_scope_policy(
    *,
    tenant_id: str,
    scope_type: str,
    scope_candidates: Sequence[str],
    status: str = "ACTIVE",
) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    seen: set[str] = set()
    for scope_id in scope_candidates:
        normalized_scope_id = _normalise_scope_id(scope_id)
        if normalized_scope_id in seen:
            continue
        seen.add(normalized_scope_id)
        row = storage.fetchone(
            """
            SELECT tenant_id, policy_id, scope_type, scope_id, version, status,
                   policy_hash, policy_json, lint_errors_json, lint_warnings_json,
                   rollout_percentage, rollout_scope,
                   created_at, created_by, activated_at, activated_by, archived_at, supersedes_policy_id
            FROM policy_registry_entries
            WHERE tenant_id = ?
              AND scope_type = ?
              AND scope_id = ?
              AND status = ?
            ORDER BY activated_at DESC, created_at DESC
            LIMIT 1
            """,
            (tenant_id, scope_type, normalized_scope_id, _normalise_status(status)),
        )
        if row:
            return _serialize_policy_row(row)
    return None


def _rollout_bucket(*, policy_id: str, rollout_key: str, scope_type: str, scope_id: str) -> int:
    material = {
        "policy_id": policy_id,
        "rollout_key": rollout_key,
        "scope_type": scope_type,
        "scope_id": scope_id,
    }
    digest = sha256_json(material)
    return int(digest[:16], 16) % 100


def _select_policy_for_rollout(
    *,
    tenant_id: str,
    policy: Dict[str, Any],
    rollout_key: str,
) -> Dict[str, Any]:
    rollout_percentage = _normalise_rollout_percentage(policy.get("rollout_percentage"))
    if rollout_percentage >= 100:
        selected = dict(policy)
        selected["rollout"] = {
            "enabled": False,
            "selected": True,
            "percentage": rollout_percentage,
        }
        return selected

    bucket = _rollout_bucket(
        policy_id=str(policy.get("policy_id") or ""),
        rollout_key=rollout_key,
        scope_type=str(policy.get("scope_type") or ""),
        scope_id=str(policy.get("scope_id") or ""),
    )
    selected = bucket < rollout_percentage
    if selected:
        out = dict(policy)
        out["rollout"] = {
            "enabled": True,
            "selected": True,
            "percentage": rollout_percentage,
            "bucket": bucket,
            "fallback_policy_id": None,
        }
        return out

    fallback = _latest_scope_policy(
        tenant_id=tenant_id,
        scope_type=str(policy.get("scope_type") or ""),
        scope_candidates=[str(policy.get("scope_id") or "")],
        status="ARCHIVED",
    )
    if not fallback:
        fallback = _latest_scope_policy(
            tenant_id=tenant_id,
            scope_type=str(policy.get("scope_type") or ""),
            scope_candidates=[str(policy.get("scope_id") or "")],
            status="DEPRECATED",
        )
    if fallback:
        fallback = dict(fallback)
        fallback["rollout"] = {
            "enabled": True,
            "selected": False,
            "percentage": rollout_percentage,
            "bucket": bucket,
            "fallback_policy_id": fallback.get("policy_id"),
            "superseded_by": policy.get("policy_id"),
        }
        return fallback

    skipped = dict(policy)
    skipped["rollout"] = {
        "enabled": True,
        "selected": False,
        "percentage": rollout_percentage,
        "bucket": bucket,
        "fallback_policy_id": None,
        "skipped": True,
    }
    skipped["status"] = "SKIPPED"
    return skipped


def _resolve_scope_component(
    *,
    tenant_id: str,
    scope_type: str,
    scope_candidates: Sequence[str],
    status_filter: str,
) -> Optional[Dict[str, Any]]:
    normalized_filter = _normalise_resolve_status(status_filter)
    if normalized_filter == "STAGED":
        staged = _latest_scope_policy(
            tenant_id=tenant_id,
            scope_type=scope_type,
            scope_candidates=scope_candidates,
            status="STAGED",
        )
        if staged:
            staged_component = dict(staged)
            staged_component["resolved_from_status"] = "STAGED"
            return staged_component
        active_fallback = _latest_scope_policy(
            tenant_id=tenant_id,
            scope_type=scope_type,
            scope_candidates=scope_candidates,
            status="ACTIVE",
        )
        if active_fallback:
            fallback_component = dict(active_fallback)
            fallback_component["resolved_from_status"] = "ACTIVE"
            return fallback_component
        return None

    active = _latest_scope_policy(
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_candidates=scope_candidates,
        status="ACTIVE",
    )
    if not active:
        return None
    component = dict(active)
    component["resolved_from_status"] = "ACTIVE"
    return component


def resolve_registry_policy(
    *,
    tenant_id: Optional[str],
    org_id: Optional[str],
    project_id: Optional[str],
    workflow_id: Optional[str],
    transition_id: Optional[str],
    rollout_key: Optional[str] = None,
    status_filter: str = "ACTIVE",
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_status_filter = _normalise_resolve_status(status_filter)

    input_rollout_key = str(rollout_key or "").strip()
    if not input_rollout_key:
        input_rollout_key = f"{org_id or '*'}|{project_id or '*'}|{workflow_id or '*'}|{transition_id or '*'}"

    scope_lookup = [
        ("org", [org_id, effective_tenant, "default", "*"]),
        ("project", [project_id, "default", "*"]),
        ("workflow", [workflow_id, "default", "*"]),
        ("transition", [transition_id, "default", "*"]),
    ]

    effective_policy: Dict[str, Any] = {}
    selected_components: List[Dict[str, Any]] = []
    resolution_conflicts: List[Dict[str, Any]] = []

    for scope_type, candidates in scope_lookup:
        filtered_candidates = [str(value).strip() for value in candidates if str(value or "").strip()]
        if not filtered_candidates:
            continue
        selected_for_scope = _resolve_scope_component(
            tenant_id=effective_tenant,
            scope_type=scope_type,
            scope_candidates=filtered_candidates,
            status_filter=normalized_status_filter,
        )
        if not selected_for_scope:
            continue
        selected = _select_policy_for_rollout(
            tenant_id=effective_tenant,
            policy=selected_for_scope,
            rollout_key=input_rollout_key,
        )
        if str(selected.get("status") or "").upper() == "SKIPPED":
            continue
        policy_fragment = selected.get("policy_json")
        if not isinstance(policy_fragment, dict):
            continue
        parent_scope = selected_components[-1]["scope_type"] if selected_components else "baseline"
        conflicts = _monotonic_conflicts(
            base_policy=effective_policy,
            incoming_policy=policy_fragment,
            from_scope=str(parent_scope),
            to_scope=scope_type,
        )
        if conflicts:
            resolution_conflicts.extend(conflicts)
            selected = dict(selected)
            selected["inheritance_conflicts"] = conflicts
            selected["policy_json_effective"] = policy_fragment
        effective_policy = deep_merge_policies(effective_policy, policy_fragment)
        selected_components.append(selected)

    effective_policy = json.loads(canonical_json(effective_policy))
    effective_policy_hash = _policy_hash(effective_policy)
    component_policy_ids = [str(component.get("policy_id") or "") for component in selected_components if component.get("policy_id")]
    component_lineage: Dict[str, Dict[str, Any]] = {}
    for component in selected_components:
        scope = str(component.get("scope_type") or "").strip().lower()
        if scope not in SCOPE_PRECEDENCE:
            continue
        component_lineage[scope] = {
            "policy_id": component.get("policy_id"),
            "version": component.get("version"),
            "scope_id": component.get("scope_id"),
            "policy_hash": component.get("policy_hash"),
            "status": component.get("status"),
            "resolved_from_status": component.get("resolved_from_status"),
        }

    return {
        "tenant_id": effective_tenant,
        "status_filter": normalized_status_filter,
        "resolution_inputs": {
            "org_id": org_id,
            "project_id": project_id,
            "workflow_id": workflow_id,
            "transition_id": transition_id,
            "rollout_key": input_rollout_key,
        },
        "effective_policy": effective_policy,
        "effective_policy_hash": effective_policy_hash,
        "component_policy_ids": component_policy_ids,
        "component_lineage": component_lineage,
        "components": selected_components,
        "resolution_conflicts": resolution_conflicts,
    }


def activate_registry_policy(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    actor_id: Optional[str],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()

    policy = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not policy:
        raise ValueError("policy not found")

    current_status = _normalise_status(policy.get("status"))
    if current_status == PolicyStatus.ACTIVE.value:
        return policy
    if current_status == PolicyStatus.DRAFT.value:
        raise ValueError("policy must be staged before activation")
    _assert_transition_allowed(from_status=current_status, to_status=PolicyStatus.ACTIVE.value, action="activate")
    _ensure_monotonic_policy(
        tenant_id=effective_tenant,
        scope_type=str(policy.get("scope_type") or ""),
        scope_id=str(policy.get("scope_id") or ""),
        policy_json=policy.get("policy_json") if isinstance(policy.get("policy_json"), dict) else {},
        stage="activate",
    )
    validation = _validate_policy_ready_for_activation(
        tenant_id=effective_tenant,
        policy=policy,
    )

    now_iso = _utc_now()
    supersedes_policy_id: Optional[str] = None
    with storage.transaction() as tx:
        previous = tx.fetchone(
            """
            SELECT policy_id
            FROM policy_registry_entries
            WHERE tenant_id = ? AND scope_type = ? AND scope_id = ? AND status = 'ACTIVE' AND policy_id != ?
            ORDER BY activated_at DESC, created_at DESC
            LIMIT 1
            """,
            (
                effective_tenant,
                policy["scope_type"],
                policy["scope_id"],
                str(policy_id),
            ),
        )
        supersedes_policy_id = str((previous or {}).get("policy_id") or "") or None
        tx.execute(
            """
            UPDATE policy_registry_entries
            SET status = 'ARCHIVED', archived_at = COALESCE(archived_at, ?)
            WHERE tenant_id = ? AND scope_type = ? AND scope_id = ? AND status = 'ACTIVE' AND policy_id != ?
            """,
            (
                now_iso,
                effective_tenant,
                policy["scope_type"],
                policy["scope_id"],
                str(policy_id),
            ),
        )
        tx.execute(
            """
            UPDATE policy_registry_entries
            SET status = 'ACTIVE',
                activated_at = ?,
                activated_by = ?,
                archived_at = NULL,
                supersedes_policy_id = ?
            WHERE tenant_id = ? AND policy_id = ?
            """,
            (
                now_iso,
                str(actor_id or "") or None,
                supersedes_policy_id,
                effective_tenant,
                str(policy_id),
            ),
        )

    activated = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not activated:
        raise ValueError("policy activation failed")
    if supersedes_policy_id:
        superseded = get_registry_policy(tenant_id=effective_tenant, policy_id=str(supersedes_policy_id))
        append_registry_event(
            tenant_id=effective_tenant,
            policy_id=str(supersedes_policy_id),
            event_type="POLICY_ARCHIVED",
            actor_id=actor_id,
            metadata={
                "scope_type": policy.get("scope_type"),
                "scope_id": policy.get("scope_id"),
                "policy_hash": (superseded or {}).get("policy_hash"),
                "reason": "superseded",
                "superseded_by": str(policy_id),
                "superseded_by_hash": policy.get("policy_hash"),
            },
        )
    append_registry_event(
        tenant_id=effective_tenant,
        policy_id=str(policy_id),
        event_type="POLICY_ACTIVATED",
        actor_id=actor_id,
        metadata={
            "scope_type": policy.get("scope_type"),
            "scope_id": policy.get("scope_id"),
            "policy_hash": policy.get("policy_hash"),
            "effective_policy_hash": validation.get("effective_policy_hash"),
            "component_policy_ids": validation.get("component_policy_ids"),
            "from_status": current_status,
            "to_status": PolicyStatus.ACTIVE.value,
            "supersedes_policy_id": supersedes_policy_id,
        },
    )
    return activated


def archive_registry_policy(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    actor_id: Optional[str],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    existing = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not existing:
        raise ValueError("policy not found")
    current_status = _normalise_status(existing.get("status"))
    if current_status == PolicyStatus.ACTIVE.value:
        raise ValueError("active policies cannot be archived")
    if current_status == PolicyStatus.ARCHIVED.value:
        return existing
    _assert_transition_allowed(from_status=current_status, to_status=PolicyStatus.ARCHIVED.value, action="archive")

    now_iso = _utc_now()
    storage.execute(
        """
        UPDATE policy_registry_entries
        SET status = 'ARCHIVED',
            archived_at = COALESCE(archived_at, ?),
            activated_at = COALESCE(activated_at, ?),
            activated_by = COALESCE(activated_by, ?)
        WHERE tenant_id = ? AND policy_id = ?
        """,
        (now_iso, now_iso, str(actor_id or "") or None, effective_tenant, str(policy_id)),
    )
    archived = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not archived:
        raise ValueError("policy archive failed")
    append_registry_event(
        tenant_id=effective_tenant,
        policy_id=str(policy_id),
        event_type="POLICY_ARCHIVED",
        actor_id=actor_id,
        metadata={
            "scope_type": existing.get("scope_type"),
            "scope_id": existing.get("scope_id"),
            "policy_hash": existing.get("policy_hash"),
            "from_status": current_status,
            "to_status": PolicyStatus.ARCHIVED.value,
        },
    )
    return archived


def rollback_registry_policy(
    *,
    tenant_id: Optional[str],
    policy_id: str,
    actor_id: Optional[str],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    current = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not current:
        raise ValueError("policy not found")
    if _normalise_status(current.get("status")) != PolicyStatus.ACTIVE.value:
        raise ValueError("rollback requires an active policy id")

    scope_type = str(current.get("scope_type") or "")
    scope_id = str(current.get("scope_id") or "")
    previous_id = str(current.get("supersedes_policy_id") or "").strip()
    if previous_id:
        previous = get_registry_policy(tenant_id=effective_tenant, policy_id=previous_id)
    else:
        previous = None
    if not previous or _normalise_status(previous.get("status")) != PolicyStatus.ARCHIVED.value:
        row = storage.fetchone(
            """
            SELECT tenant_id, policy_id, scope_type, scope_id, version, status,
                   policy_hash, policy_json, lint_errors_json, lint_warnings_json,
                   rollout_percentage, rollout_scope,
                   created_at, created_by, activated_at, activated_by, archived_at, supersedes_policy_id
            FROM policy_registry_entries
            WHERE tenant_id = ? AND scope_type = ? AND scope_id = ? AND policy_id != ? AND status = 'ARCHIVED'
            ORDER BY activated_at DESC, archived_at DESC, created_at DESC
            LIMIT 1
            """,
            (effective_tenant, scope_type, scope_id, str(policy_id)),
        )
        previous = _serialize_policy_row(row) if row else None
    if not previous:
        raise ValueError("no previous archived policy available for rollback")

    now_iso = _utc_now()
    with storage.transaction() as tx:
        tx.execute(
            """
            UPDATE policy_registry_entries
            SET status = 'ARCHIVED', archived_at = COALESCE(archived_at, ?)
            WHERE tenant_id = ? AND policy_id = ?
            """,
            (now_iso, effective_tenant, str(policy_id)),
        )
        tx.execute(
            """
            UPDATE policy_registry_entries
            SET status = 'ACTIVE',
                activated_at = ?,
                activated_by = ?,
                archived_at = NULL,
                supersedes_policy_id = ?
            WHERE tenant_id = ? AND policy_id = ?
            """,
            (
                now_iso,
                str(actor_id or "") or None,
                str(policy_id),
                effective_tenant,
                str(previous.get("policy_id") or ""),
            ),
        )

    append_registry_event(
        tenant_id=effective_tenant,
        policy_id=str(policy_id),
        event_type="POLICY_ARCHIVED",
        actor_id=actor_id,
        metadata={
            "scope_type": scope_type,
            "scope_id": scope_id,
            "policy_hash": current.get("policy_hash"),
            "reason": "rollback",
            "rollback_to_policy_id": str(previous.get("policy_id") or ""),
            "rollback_to_policy_hash": previous.get("policy_hash"),
        },
    )
    append_registry_event(
        tenant_id=effective_tenant,
        policy_id=str(previous.get("policy_id") or ""),
        event_type="POLICY_ROLLBACK",
        actor_id=actor_id,
        metadata={
            "scope_type": scope_type,
            "scope_id": scope_id,
            "policy_hash": previous.get("policy_hash"),
            "rolled_back_from_policy_id": str(policy_id),
            "rolled_back_from_policy_hash": current.get("policy_hash"),
        },
    )
    restored = get_registry_policy(tenant_id=effective_tenant, policy_id=str(previous.get("policy_id") or ""))
    if not restored:
        raise ValueError("rollback activation failed")
    return restored


def simulate_registry_decision(
    *,
    tenant_id: Optional[str],
    actor: Optional[str],
    issue_key: Optional[str],
    transition_id: str,
    project_id: Optional[str],
    workflow_id: Optional[str],
    environment: Optional[str],
    context: Optional[Dict[str, Any]],
    policy_id: Optional[str] = None,
    status_filter: str = "ACTIVE",
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    env_value = str(environment or "").strip()
    context_data = dict(context or {})

    resolved: Dict[str, Any]
    if policy_id:
        selected = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
        if not selected:
            raise ValueError("policy not found")
        resolved = {
            "tenant_id": effective_tenant,
            "resolution_inputs": {
                "org_id": context_data.get("org_id") or effective_tenant,
                "project_id": project_id,
                "workflow_id": workflow_id,
                "transition_id": transition_id,
                "rollout_key": context_data.get("rollout_key") or issue_key or transition_id,
            },
            "effective_policy": selected.get("policy_json") if isinstance(selected.get("policy_json"), dict) else {},
            "effective_policy_hash": selected.get("policy_hash") or _policy_hash(selected.get("policy_json") or {}),
            "component_policy_ids": [str(selected.get("policy_id") or "")],
            "component_lineage": {
                str(selected.get("scope_type") or ""): {
                    "policy_id": selected.get("policy_id"),
                    "version": selected.get("version"),
                    "scope_id": selected.get("scope_id"),
                    "policy_hash": selected.get("policy_hash"),
                }
            },
            "components": [selected],
            "resolution_conflicts": [],
        }
    else:
        resolved = resolve_registry_policy(
            tenant_id=effective_tenant,
            org_id=str(context_data.get("org_id") or effective_tenant),
            project_id=project_id,
            workflow_id=workflow_id,
            transition_id=transition_id,
            rollout_key=context_data.get("rollout_key") or issue_key or transition_id,
            status_filter=status_filter,
        )

    effective_policy = resolved.get("effective_policy") if isinstance(resolved.get("effective_policy"), dict) else {}
    rules = effective_policy.get("transition_rules") if isinstance(effective_policy.get("transition_rules"), list) else []

    matches: List[Dict[str, Any]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if str(rule.get("transition_id") or "").strip() not in {"", str(transition_id)}:
            continue
        if project_id and str(rule.get("project_id") or "").strip() not in {"", str(project_id)}:
            continue
        if workflow_id and str(rule.get("workflow_id") or "").strip() not in {"", str(workflow_id)}:
            continue
        if env_value and str(rule.get("environment") or "").strip().lower() not in {"", env_value.lower()}:
            continue
        matches.append(
            {
                "rule": rule,
                "priority": int(rule.get("priority") or 1000),
                "index": index,
            }
        )

    matches.sort(key=lambda entry: (entry["priority"], entry["index"]))
    selected_rule = matches[0]["rule"] if matches else None
    strict_fail_closed = bool(effective_policy.get("strict_fail_closed", True))

    reason_codes: List[str] = []
    status = "ALLOWED"
    allow = True

    if selected_rule:
        result = str(selected_rule.get("result") or selected_rule.get("enforcement") or "ALLOW").strip().upper()
        if result in {"BLOCK", "BLOCKED", "DENY", "DENIED"}:
            allow = False
            status = "BLOCKED"
            reason_codes.append("POLICY_DENIED")
        elif result in {"WARN", "CONDITIONAL"}:
            allow = True
            status = "CONDITIONAL"
            reason_codes.append("POLICY_CONDITIONAL")
        else:
            allow = True
            status = "ALLOWED"
            reason_codes.append("POLICY_ALLOWED")
    else:
        default_result = str(effective_policy.get("default_result") or "ALLOW").strip().upper()
        if strict_fail_closed and default_result not in {"ALLOW", "ALLOWED", "COMPLIANT"}:
            allow = False
            status = "BLOCKED"
            reason_codes.append("NO_MATCHING_RULE")
        else:
            allow = True
            status = "ALLOWED"
            reason_codes.append("NO_MATCHING_RULE")

    return {
        "tenant_id": effective_tenant,
        "allow": allow,
        "status": status,
        "reason_codes": sorted(set(reason_codes)),
        "policy_hash": resolved.get("effective_policy_hash"),
        "effective_policy_hash": resolved.get("effective_policy_hash"),
        "component_policy_ids": resolved.get("component_policy_ids", []),
        "component_lineage": resolved.get("component_lineage", {}),
        "resolution_conflicts": resolved.get("resolution_conflicts", []),
        "effective_policy_json": effective_policy,
        "resolution_inputs": resolved.get("resolution_inputs", {}),
        "status_filter": resolved.get("status_filter", _normalise_resolve_status(status_filter)),
        "matched_rule": selected_rule,
        "actor": actor,
        "issue_key": issue_key,
        "transition_id": transition_id,
        "project_id": project_id,
        "workflow_id": workflow_id,
        "environment": environment,
    }
