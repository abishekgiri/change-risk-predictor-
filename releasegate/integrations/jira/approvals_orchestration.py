from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.audit.reader import AuditReader
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_role(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalize_group_name(value: Any) -> str:
    return str(value or "").strip().lower()


def _reason_min_length_default() -> int:
    raw = str(os.getenv("RELEASEGATE_APPROVAL_REASON_MIN_LENGTH") or "40").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 40


def build_approval_scope_payload(
    *,
    tenant_id: str,
    issue_key: str,
    transition_id: str,
    source_status: str,
    target_status: str,
    environment: Optional[str],
    project_key: Optional[str],
    policy_hash: str,
    actor_account_id: Optional[str] = None,
    commit_sha: Optional[str] = None,
    artifact_digest: Optional[str] = None,
    risk_level: Optional[str] = None,
    risk_score: Optional[float] = None,
    risk_reason_codes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    rounded_score: Optional[float] = None
    if isinstance(risk_score, (int, float)):
        rounded_score = round(float(risk_score), 3)
    reasons = sorted(
        {
            str(code).strip().upper()
            for code in (risk_reason_codes or [])
            if str(code or "").strip()
        }
    )
    return {
        "tenant_id": str(tenant_id or "").strip(),
        "jira_issue_id": str(issue_key or "").strip(),
        "transition_id": str(transition_id or "").strip(),
        "source_status": str(source_status or "").strip(),
        "target_status": str(target_status or "").strip(),
        "environment": str(environment or "").strip(),
        "project_key": str(project_key or "").strip(),
        "policy_hash": str(policy_hash or "").strip(),
        "actor_account_id": str(actor_account_id or "").strip(),
        "commit_sha": str(commit_sha or "").strip(),
        "artifact_digest": str(artifact_digest or "").strip(),
        "risk_summary": {
            "risk_level": str(risk_level or "").strip().upper(),
            "risk_score": rounded_score,
            "risk_reason_codes": reasons,
        },
        "schema": "approval_scope_v1",
    }


def compute_approval_scope_hash(payload: Dict[str, Any]) -> str:
    canonical = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def normalize_approval_justification(
    justification: Dict[str, Any],
    *,
    reason_required: bool = True,
    reason_min_length: Optional[int] = None,
    required_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if not isinstance(justification, dict):
        raise ValueError("JUSTIFICATION_INVALID")

    minimum = max(1, int(reason_min_length or _reason_min_length_default()))
    reason = str(justification.get("reason") or "").strip()
    if reason_required and not reason:
        raise ValueError("JUSTIFICATION_MISSING")
    if reason and len(reason) < minimum:
        raise ValueError("JUSTIFICATION_TOO_SHORT")

    normalized: Dict[str, Any] = {
        "reason": reason,
        "risk_acknowledgement": bool(justification.get("risk_acknowledgement", False)),
        "impact": str(justification.get("impact") or "").strip(),
        "references": sorted(
            {
                str(item).strip()
                for item in (justification.get("references") or [])
                if str(item or "").strip()
            }
        )
        if isinstance(justification.get("references"), list)
        else [],
    }

    required = [
        str(field).strip()
        for field in (required_fields or [])
        if str(field or "").strip()
    ]
    for field in required:
        value = normalized.get(field)
        if field == "reason" and reason_required:
            if not str(value or "").strip():
                raise ValueError("JUSTIFICATION_FIELD_REQUIRED")
            continue
        if isinstance(value, list) and not value:
            raise ValueError("JUSTIFICATION_FIELD_REQUIRED")
        if isinstance(value, bool):
            # Explicit False is allowed for boolean fields.
            continue
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValueError("JUSTIFICATION_FIELD_REQUIRED")

    return normalized


def _extract_policy_from_decision(decision_row: Dict[str, Any]) -> Dict[str, Any]:
    raw_full = decision_row.get("full_decision_json")
    payload: Dict[str, Any] = {}
    if isinstance(raw_full, dict):
        payload = raw_full
    elif isinstance(raw_full, str) and raw_full.strip():
        try:
            parsed = json.loads(raw_full)
            if isinstance(parsed, dict):
                payload = parsed
        except Exception:
            payload = {}
    snapshot = payload.get("input_snapshot")
    if not isinstance(snapshot, dict):
        return {}
    registry = snapshot.get("registry_policy")
    if not isinstance(registry, dict):
        return {}
    effective = registry.get("effective_policy")
    if not isinstance(effective, dict):
        return {}
    return effective


def extract_scope_hash_from_decision(decision_row: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    raw_full = decision_row.get("full_decision_json")
    payload: Dict[str, Any] = {}
    if isinstance(raw_full, dict):
        payload = raw_full
    elif isinstance(raw_full, str) and raw_full.strip():
        try:
            parsed = json.loads(raw_full)
            if isinstance(parsed, dict):
                payload = parsed
        except Exception:
            payload = {}
    snapshot = payload.get("input_snapshot")
    if not isinstance(snapshot, dict):
        return "", {}
    approval_scope = snapshot.get("approval_scope")
    if not isinstance(approval_scope, dict):
        return "", {}
    scope_hash = str(approval_scope.get("hash") or "").strip()
    scope_payload = approval_scope.get("payload")
    if not isinstance(scope_payload, dict):
        scope_payload = {}
    if not scope_hash and scope_payload:
        scope_hash = compute_approval_scope_hash(scope_payload)
    return scope_hash, scope_payload


def resolve_justification_requirements_from_decision(decision_row: Dict[str, Any]) -> Dict[str, Any]:
    policy = _extract_policy_from_decision(decision_row)
    approval_cfg = policy.get("approval_requirements") if isinstance(policy.get("approval_requirements"), dict) else {}
    approvals_cfg = policy.get("approvals") if isinstance(policy.get("approvals"), dict) else {}
    justification_cfg = approval_cfg.get("justification") if isinstance(approval_cfg.get("justification"), dict) else {}
    if not justification_cfg and isinstance(approvals_cfg.get("justification"), dict):
        justification_cfg = approvals_cfg.get("justification")  # type: ignore[assignment]

    reason_required = bool(justification_cfg.get("reason_required", True))
    min_length_raw = justification_cfg.get("reason_min_length")
    try:
        min_length = max(1, int(min_length_raw)) if min_length_raw is not None else _reason_min_length_default()
    except Exception:
        min_length = _reason_min_length_default()
    required_fields = [
        str(item).strip()
        for item in (justification_cfg.get("required_fields") or [])
        if str(item or "").strip()
    ] if isinstance(justification_cfg.get("required_fields"), list) else []
    return {
        "reason_required": reason_required,
        "reason_min_length": min_length,
        "required_fields": required_fields,
    }


def create_decision_approval(
    *,
    tenant_id: str,
    decision_id: str,
    approver_actor: str,
    approver_role: Optional[str],
    approval_group: Optional[str],
    justification: Dict[str, Any],
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_row = AuditReader.get_decision(decision_id=decision_id, tenant_id=effective_tenant)
    if not decision_row:
        raise ValueError("DECISION_NOT_FOUND")

    scope_hash, scope_payload = extract_scope_hash_from_decision(decision_row)
    if not scope_hash:
        raise ValueError("APPROVAL_SCOPE_UNAVAILABLE")

    requirements = resolve_justification_requirements_from_decision(decision_row)
    normalized_justification = normalize_approval_justification(
        justification,
        reason_required=bool(requirements.get("reason_required", True)),
        reason_min_length=int(requirements.get("reason_min_length") or _reason_min_length_default()),
        required_fields=list(requirements.get("required_fields") or []),
    )

    normalized_actor = str(approver_actor or "").strip()
    if not normalized_actor:
        raise ValueError("APPROVER_REQUIRED")
    normalized_role = _normalize_role(approver_role)
    normalized_group = _normalize_group_name(approval_group)
    normalized_request_id = str(request_id or "").strip() or None
    justification_json = canonical_json(normalized_justification)
    justification_hash = hashlib.sha256(justification_json.encode("utf-8")).hexdigest()
    approval_id = str(uuid.uuid4())
    created_at = _utc_now_iso()

    if normalized_request_id:
        existing_by_request = storage.fetchone(
            """
            SELECT *
            FROM decision_approvals
            WHERE tenant_id = ? AND request_id = ?
            """,
            (effective_tenant, normalized_request_id),
        )
        if existing_by_request:
            return existing_by_request

    existing = storage.fetchone(
        """
        SELECT *
        FROM decision_approvals
        WHERE tenant_id = ?
          AND approval_scope_hash = ?
          AND approver_actor = ?
          AND COALESCE(approval_group, '') = COALESCE(?, '')
          AND revoked_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (
            effective_tenant,
            scope_hash,
            normalized_actor,
            normalized_group or None,
        ),
    )
    if existing:
        return existing

    storage.execute(
        """
        INSERT INTO decision_approvals (
            tenant_id,
            approval_id,
            decision_id,
            approval_scope_hash,
            approval_scope_json,
            approval_group,
            approver_actor,
            approver_role,
            justification_json,
            justification_hash,
            request_id,
            created_at,
            revoked_at,
            revoked_reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
        """,
        (
            effective_tenant,
            approval_id,
            decision_id,
            scope_hash,
            canonical_json(scope_payload),
            normalized_group or None,
            normalized_actor,
            normalized_role or None,
            justification_json,
            justification_hash,
            normalized_request_id,
            created_at,
        ),
    )
    inserted = storage.fetchone(
        """
        SELECT *
        FROM decision_approvals
        WHERE tenant_id = ? AND approval_id = ?
        """,
        (effective_tenant, approval_id),
    )
    if not inserted:
        raise RuntimeError("APPROVAL_INSERT_FAILED")
    return inserted


def list_active_scope_approvals(*, tenant_id: str, approval_scope_hash: str, limit: int = 500) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    return storage.fetchall(
        """
        SELECT *
        FROM decision_approvals
        WHERE tenant_id = ?
          AND approval_scope_hash = ?
          AND revoked_at IS NULL
        ORDER BY created_at ASC
        LIMIT ?
        """,
        (effective_tenant, str(approval_scope_hash or "").strip(), max(1, min(int(limit), 2000))),
    )


def normalize_cab_groups(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(policy, dict):
        return []
    groups: List[Any] = []

    approval_cfg = policy.get("approval_requirements")
    if isinstance(approval_cfg, dict) and isinstance(approval_cfg.get("groups"), list):
        groups.extend(approval_cfg.get("groups") or [])
    approvals_cfg = policy.get("approvals")
    if isinstance(approvals_cfg, dict) and isinstance(approvals_cfg.get("groups"), list):
        groups.extend(approvals_cfg.get("groups") or [])
    if isinstance(policy.get("approval_groups"), list):
        groups.extend(policy.get("approval_groups") or [])

    normalized: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for entry in groups:
        if not isinstance(entry, dict):
            continue
        name = _normalize_group_name(entry.get("name") or entry.get("group"))
        if not name or name in seen:
            continue
        seen.add(name)
        try:
            min_approvals = max(0, int(entry.get("min_approvals", 0) or 0))
        except Exception:
            min_approvals = 0
        try:
            min_unique_roles = max(0, int(entry.get("min_unique_roles", 0) or 0))
        except Exception:
            min_unique_roles = 0
        if bool(entry.get("require_cross_functional", False)) and min_unique_roles < 2:
            min_unique_roles = 2
        allowed_roles = sorted(
            {
                _normalize_role(role)
                for role in (entry.get("allowed_roles") or [])
                if _normalize_role(role)
            }
        ) if isinstance(entry.get("allowed_roles"), list) else []
        normalized.append(
            {
                "name": name,
                "min_approvals": min_approvals,
                "min_unique_roles": min_unique_roles,
                "allowed_roles": allowed_roles,
                "require_cross_functional": bool(entry.get("require_cross_functional", False)),
                "forbid_same_actor_as_submitter": bool(entry.get("forbid_same_actor_as_submitter", False)),
            }
        )
    return normalized


def evaluate_cab_groups(
    *,
    groups: List[Dict[str, Any]],
    approvals: List[Dict[str, Any]],
    submitter_actor: Optional[str],
) -> Dict[str, Any]:
    if not groups:
        return {"required": False, "satisfied": True, "group_results": [], "missing_requirements": []}

    submitter = str(submitter_actor or "").strip().lower()
    group_results: List[Dict[str, Any]] = []
    missing: List[str] = []

    for group in groups:
        group_name = _normalize_group_name(group.get("name"))
        allowed_roles = {
            _normalize_role(role)
            for role in (group.get("allowed_roles") or [])
            if _normalize_role(role)
        }
        selected: List[Dict[str, Any]] = []
        for approval in approvals:
            approval_group = _normalize_group_name(approval.get("approval_group"))
            if approval_group != group_name:
                continue
            actor = str(approval.get("approver_actor") or "").strip().lower()
            if not actor:
                continue
            if group.get("forbid_same_actor_as_submitter") and submitter and actor == submitter:
                continue
            role = _normalize_role(approval.get("approver_role"))
            if allowed_roles and role not in allowed_roles:
                continue
            selected.append(approval)

        actors = sorted({str(item.get("approver_actor") or "").strip().lower() for item in selected if str(item.get("approver_actor") or "").strip()})
        roles = sorted({_normalize_role(item.get("approver_role")) for item in selected if _normalize_role(item.get("approver_role"))})
        min_approvals = max(0, int(group.get("min_approvals") or 0))
        min_unique_roles = max(0, int(group.get("min_unique_roles") or 0))
        satisfied = len(actors) >= min_approvals and len(roles) >= min_unique_roles
        if not satisfied:
            missing.append(
                f"CAB group `{group_name}` requires {min_approvals} approvals and {min_unique_roles} unique roles."
            )
        group_results.append(
            {
                "name": group_name,
                "required_min_approvals": min_approvals,
                "required_min_unique_roles": min_unique_roles,
                "actual_approvals": len(actors),
                "actual_unique_roles": len(roles),
                "allowed_roles": sorted(allowed_roles),
                "actors": actors,
                "roles": roles,
                "satisfied": satisfied,
            }
        )

    return {
        "required": True,
        "satisfied": not missing,
        "group_results": group_results,
        "missing_requirements": missing,
    }
