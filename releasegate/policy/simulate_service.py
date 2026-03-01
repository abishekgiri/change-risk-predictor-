from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.policy.conflict_engine import analyze_policy_conflicts
from releasegate.policy.registry import get_registry_policy, resolve_registry_policy
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        except Exception:
            return fallback
    return fallback


def _evaluate_effective_policy(
    *,
    effective_policy: Dict[str, Any],
    transition_id: str,
    project_id: Optional[str],
    workflow_id: Optional[str],
    environment: Optional[str],
) -> Dict[str, Any]:
    env_value = str(environment or "").strip().lower()
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
        if env_value and str(rule.get("environment") or "").strip().lower() not in {"", env_value}:
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
        "allow": allow,
        "status": status,
        "reason_codes": sorted(set(reason_codes)),
        "matched_rule": selected_rule,
    }


def _record_simulation_event(
    *,
    tenant_id: str,
    simulation_id: str,
    actor_id: Optional[str],
    policy_id: Optional[str],
    policy_version: Optional[int],
    policy_hash: str,
    environment: Optional[str],
    input_hash: str,
    result_status: str,
    allow: bool,
    reason_codes: List[str],
    summary: Dict[str, Any],
) -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO policy_simulation_events (
            tenant_id, simulation_id, actor_id, policy_id, policy_version,
            policy_hash, environment, input_hash, result_status, allow,
            reason_codes_json, summary_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            simulation_id,
            str(actor_id or "") or None,
            str(policy_id or "") or None,
            int(policy_version) if policy_version is not None else None,
            policy_hash,
            str(environment or "") or None,
            input_hash,
            result_status,
            1 if allow else 0,
            canonical_json(reason_codes),
            canonical_json(summary),
            _utc_now(),
        ),
    )


def _policy_by_id_and_version(*, tenant_id: str, policy_id: str, version: int) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, policy_id, version, status, policy_hash, policy_json,
               scope_type, scope_id, created_at
        FROM policy_registry_entries
        WHERE tenant_id = ? AND policy_id = ? AND version = ?
        LIMIT 1
        """,
        (tenant_id, str(policy_id), int(version)),
    )
    if not row:
        return None
    return {
        "tenant_id": row.get("tenant_id"),
        "policy_id": row.get("policy_id"),
        "version": row.get("version"),
        "status": row.get("status"),
        "policy_hash": row.get("policy_hash"),
        "policy_json": _parse_json_field(row.get("policy_json"), {}),
        "scope_type": row.get("scope_type"),
        "scope_id": row.get("scope_id"),
        "created_at": row.get("created_at"),
    }


def simulate_policy_decision(
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
    policy_version: Optional[int] = None,
    policy_json: Optional[Dict[str, Any]] = None,
    status_filter: str = "ACTIVE",
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    context_data = dict(context or {})

    resolved: Dict[str, Any]
    selected_policy_id: Optional[str] = None
    selected_policy_version: Optional[int] = None

    if isinstance(policy_json, dict) and policy_json:
        effective_policy = json.loads(canonical_json(policy_json))
        policy_hash = sha256_json(effective_policy)
        resolved = {
            "tenant_id": effective_tenant,
            "status_filter": "EXPLICIT",
            "resolution_inputs": {
                "org_id": context_data.get("org_id") or effective_tenant,
                "project_id": project_id,
                "workflow_id": workflow_id,
                "transition_id": transition_id,
                "rollout_key": context_data.get("rollout_key") or issue_key or transition_id,
            },
            "effective_policy": effective_policy,
            "effective_policy_hash": policy_hash,
            "component_policy_ids": [],
            "component_lineage": {},
            "components": [],
            "resolution_conflicts": [],
        }
    elif policy_id and policy_version is not None:
        selected = _policy_by_id_and_version(
            tenant_id=effective_tenant,
            policy_id=policy_id,
            version=int(policy_version),
        )
        if not selected:
            raise ValueError("policy version not found")
        selected_policy_id = str(selected.get("policy_id") or "") or None
        selected_policy_version = int(selected.get("version") or 0)
        effective_policy = selected.get("policy_json") if isinstance(selected.get("policy_json"), dict) else {}
        policy_hash = str(selected.get("policy_hash") or sha256_json(effective_policy))
        resolved = {
            "tenant_id": effective_tenant,
            "status_filter": "VERSION",
            "resolution_inputs": {
                "org_id": context_data.get("org_id") or effective_tenant,
                "project_id": project_id,
                "workflow_id": workflow_id,
                "transition_id": transition_id,
                "rollout_key": context_data.get("rollout_key") or issue_key or transition_id,
            },
            "effective_policy": effective_policy,
            "effective_policy_hash": policy_hash,
            "component_policy_ids": [selected_policy_id] if selected_policy_id else [],
            "component_lineage": {
                str(selected.get("scope_type") or ""): {
                    "policy_id": selected.get("policy_id"),
                    "version": selected.get("version"),
                    "scope_id": selected.get("scope_id"),
                    "policy_hash": selected.get("policy_hash"),
                }
            }
            if selected.get("scope_type")
            else {},
            "components": [selected],
            "resolution_conflicts": [],
        }
    elif policy_id:
        selected = get_registry_policy(tenant_id=effective_tenant, policy_id=policy_id)
        if not selected:
            raise ValueError("policy not found")
        selected_policy_id = str(selected.get("policy_id") or "") or None
        if selected.get("version") is not None:
            selected_policy_version = int(selected.get("version") or 0)
        effective_policy = selected.get("policy_json") if isinstance(selected.get("policy_json"), dict) else {}
        policy_hash = str(selected.get("policy_hash") or sha256_json(effective_policy))
        resolved = {
            "tenant_id": effective_tenant,
            "status_filter": "POLICY_ID",
            "resolution_inputs": {
                "org_id": context_data.get("org_id") or effective_tenant,
                "project_id": project_id,
                "workflow_id": workflow_id,
                "transition_id": transition_id,
                "rollout_key": context_data.get("rollout_key") or issue_key or transition_id,
            },
            "effective_policy": effective_policy,
            "effective_policy_hash": policy_hash,
            "component_policy_ids": [selected_policy_id] if selected_policy_id else [],
            "component_lineage": {
                str(selected.get("scope_type") or ""): {
                    "policy_id": selected.get("policy_id"),
                    "version": selected.get("version"),
                    "scope_id": selected.get("scope_id"),
                    "policy_hash": selected.get("policy_hash"),
                }
            }
            if selected.get("scope_type")
            else {},
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
    decision = _evaluate_effective_policy(
        effective_policy=effective_policy,
        transition_id=transition_id,
        project_id=project_id,
        workflow_id=workflow_id,
        environment=environment,
    )

    conflict_report = analyze_policy_conflicts(effective_policy)
    warning_codes = [
        str(item.get("code") or "")
        for item in conflict_report.get("warnings", [])
        if isinstance(item, dict)
    ]
    summary = {
        "status_filter": resolved.get("status_filter", status_filter),
        "component_policy_ids": resolved.get("component_policy_ids", []),
        "warning_codes": sorted({code for code in warning_codes if code}),
        "coverage_gap_count": int((conflict_report.get("summary") or {}).get("coverage_gap_count") or 0),
        "shadowed_rule_count": int((conflict_report.get("summary") or {}).get("shadowed_rule_count") or 0),
        "contradiction_count": int((conflict_report.get("summary") or {}).get("contradiction_count") or 0),
    }

    simulation_id = str(uuid.uuid4())
    input_hash = sha256_json(
        {
            "tenant_id": effective_tenant,
            "actor": actor,
            "issue_key": issue_key,
            "transition_id": transition_id,
            "project_id": project_id,
            "workflow_id": workflow_id,
            "environment": environment,
            "context": context_data,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "status_filter": status_filter,
            "explicit_policy": bool(policy_json),
        }
    )
    _record_simulation_event(
        tenant_id=effective_tenant,
        simulation_id=simulation_id,
        actor_id=actor,
        policy_id=selected_policy_id or policy_id,
        policy_version=selected_policy_version or policy_version,
        policy_hash=str(resolved.get("effective_policy_hash") or sha256_json(effective_policy)),
        environment=environment,
        input_hash=input_hash,
        result_status=str(decision.get("status") or "UNKNOWN"),
        allow=bool(decision.get("allow")),
        reason_codes=list(decision.get("reason_codes") or []),
        summary=summary,
    )

    return {
        "simulation_id": simulation_id,
        "trace_id": simulation_id,
        "enforced": False,
        "tenant_id": effective_tenant,
        "allow": bool(decision.get("allow")),
        "status": str(decision.get("status") or "UNKNOWN"),
        "reason_codes": list(decision.get("reason_codes") or []),
        "policy_hash": resolved.get("effective_policy_hash"),
        "effective_policy_hash": resolved.get("effective_policy_hash"),
        "component_policy_ids": resolved.get("component_policy_ids", []),
        "component_lineage": resolved.get("component_lineage", {}),
        "resolution_conflicts": resolved.get("resolution_conflicts", []),
        "effective_policy_json": effective_policy,
        "resolution_inputs": resolved.get("resolution_inputs", {}),
        "status_filter": resolved.get("status_filter", status_filter),
        "matched_rule": decision.get("matched_rule"),
        "warnings": conflict_report.get("warnings", []),
        "coverage_gaps": conflict_report.get("coverage_gaps", []),
        "shadowed_rules": conflict_report.get("shadowed_rules", []),
        "conflicts": conflict_report.get("contradictions", []),
        "conflict_summary": conflict_report.get("summary", {}),
        "actor": actor,
        "issue_key": issue_key,
        "transition_id": transition_id,
        "project_id": project_id,
        "workflow_id": workflow_id,
        "environment": environment,
    }
