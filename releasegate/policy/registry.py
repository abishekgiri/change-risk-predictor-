from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from releasegate.policy.inheritance import deep_merge_policies
from releasegate.policy.lint import lint_registry_policy
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


SCOPE_TYPES = {"org", "project", "workflow", "transition"}
POLICY_STATUSES = {"DRAFT", "ACTIVE", "DEPRECATED", "ARCHIVED"}
ROLLOUT_SCOPES = {"project", "workflow", "transition"}


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


def _normalise_policy_json(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("policy_json must be an object")
    return json.loads(canonical_json(payload))


def _policy_hash(policy_json: Dict[str, Any]) -> str:
    return f"sha256:{sha256_json(policy_json)}"


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
        "supersedes_policy_id": row.get("supersedes_policy_id"),
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
               created_at, created_by, activated_at, activated_by, supersedes_policy_id
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
               created_at, created_by, activated_at, activated_by, supersedes_policy_id
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
    normalized_rollout_percentage = _normalise_rollout_percentage(rollout_percentage)
    normalized_rollout_scope = _normalise_rollout_scope(rollout_scope)
    normalized_policy_json = _normalise_policy_json(policy_json)
    policy_hash = _policy_hash(normalized_policy_json)

    lint_report = lint_registry_policy(normalized_policy_json)
    lint_errors = [issue for issue in lint_report.get("issues", []) if issue.get("severity") == "ERROR"]
    lint_warnings = [issue for issue in lint_report.get("issues", []) if issue.get("severity") == "WARNING"]

    if normalized_status == "ACTIVE" and lint_errors:
        raise ValueError("policy has lint errors and cannot be activated")

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
                created_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )

    if normalized_status == "ACTIVE":
        return activate_registry_policy(
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
        "status": "DRAFT",
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
        "supersedes_policy_id": None,
    }


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
                   created_at, created_by, activated_at, activated_by, supersedes_policy_id
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


def resolve_registry_policy(
    *,
    tenant_id: Optional[str],
    org_id: Optional[str],
    project_id: Optional[str],
    workflow_id: Optional[str],
    transition_id: Optional[str],
    rollout_key: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)

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

    for scope_type, candidates in scope_lookup:
        filtered_candidates = [str(value).strip() for value in candidates if str(value or "").strip()]
        if not filtered_candidates:
            continue
        active = _latest_scope_policy(
            tenant_id=effective_tenant,
            scope_type=scope_type,
            scope_candidates=filtered_candidates,
            status="ACTIVE",
        )
        if not active:
            continue
        selected = _select_policy_for_rollout(
            tenant_id=effective_tenant,
            policy=active,
            rollout_key=input_rollout_key,
        )
        if str(selected.get("status") or "").upper() == "SKIPPED":
            continue
        policy_fragment = selected.get("policy_json")
        if not isinstance(policy_fragment, dict):
            continue
        effective_policy = deep_merge_policies(effective_policy, policy_fragment)
        selected_components.append(selected)

    effective_policy = json.loads(canonical_json(effective_policy))
    effective_policy_hash = _policy_hash(effective_policy)
    component_policy_ids = [str(component.get("policy_id") or "") for component in selected_components if component.get("policy_id")]

    return {
        "tenant_id": effective_tenant,
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
        "components": selected_components,
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

    if policy.get("lint_errors"):
        raise ValueError("policy has lint errors and cannot be activated")
    if str(policy.get("status") or "").upper() == "ACTIVE":
        return policy

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
            SET status = 'DEPRECATED'
            WHERE tenant_id = ? AND scope_type = ? AND scope_id = ? AND status = 'ACTIVE' AND policy_id != ?
            """,
            (
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
    if str(existing.get("status") or "").upper() == "ACTIVE":
        raise ValueError("active policies cannot be archived")

    storage.execute(
        """
        UPDATE policy_registry_entries
        SET status = 'ARCHIVED', activated_at = COALESCE(activated_at, ?), activated_by = COALESCE(activated_by, ?)
        WHERE tenant_id = ? AND policy_id = ?
        """,
        (now := _utc_now(), str(actor_id or "") or None, effective_tenant, str(policy_id)),
    )
    archived = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
    if not archived:
        raise ValueError("policy archive failed")
    return archived


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
            "components": [selected],
        }
    else:
        resolved = resolve_registry_policy(
            tenant_id=effective_tenant,
            org_id=str(context_data.get("org_id") or effective_tenant),
            project_id=project_id,
            workflow_id=workflow_id,
            transition_id=transition_id,
            rollout_key=context_data.get("rollout_key") or issue_key or transition_id,
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
        "effective_policy_json": effective_policy,
        "resolution_inputs": resolved.get("resolution_inputs", {}),
        "matched_rule": selected_rule,
        "actor": actor,
        "issue_key": issue_key,
        "transition_id": transition_id,
        "project_id": project_id,
        "workflow_id": workflow_id,
        "environment": environment,
    }
