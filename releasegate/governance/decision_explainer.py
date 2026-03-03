from __future__ import annotations

import json
from typing import Any, Dict, Optional

from releasegate.audit.reader import AuditReader
from releasegate.evidence.graph import explain_decision
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


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
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _request_payload(full_decision: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = full_decision.get("input_snapshot")
    if isinstance(snapshot, dict):
        request = snapshot.get("request")
        if isinstance(request, dict):
            return request
    return {}


def _signal_payload(full_decision: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = full_decision.get("input_snapshot")
    if isinstance(snapshot, dict):
        signals = snapshot.get("signal_map")
        if isinstance(signals, dict):
            return signals
    return {}


def _risk_payload(full_decision: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = full_decision.get("input_snapshot")
    if isinstance(snapshot, dict):
        risk_meta = snapshot.get("risk_meta")
        if isinstance(risk_meta, dict):
            return risk_meta
        signal_map = snapshot.get("signal_map")
        if isinstance(signal_map, dict):
            risk_signal = signal_map.get("risk")
            if isinstance(risk_signal, dict):
                return risk_signal
    return {}


def build_decision_explainer(
    *,
    tenant_id: str,
    decision_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_row = AuditReader.get_decision(decision_id, tenant_id=effective_tenant)
    if not decision_row:
        return None

    full_decision = _parse_json(decision_row.get("full_decision_json"))
    request = _request_payload(full_decision)
    signals = _signal_payload(full_decision)
    risk = _risk_payload(full_decision)
    reason_code = str(full_decision.get("reason_code") or "")
    decision_status = str(decision_row.get("release_status") or "")

    evidence = explain_decision(tenant_id=effective_tenant, decision_id=decision_id) or {}
    binding = AuditReader.get_decision_with_policy_snapshot(decision_id, tenant_id=effective_tenant) or {}
    binding_verify = AuditReader.verify_decision_policy_snapshot(decision_id, tenant_id=effective_tenant) or {}

    snapshot_wrapper = binding.get("snapshot") if isinstance(binding, dict) else {}
    snapshot = snapshot_wrapper.get("snapshot") if isinstance(snapshot_wrapper, dict) else {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    policy_bindings = full_decision.get("policy_bindings") if isinstance(full_decision.get("policy_bindings"), list) else []
    primary_binding = policy_bindings[0] if policy_bindings and isinstance(policy_bindings[0], dict) else {}

    context_overrides = request.get("context_overrides") if isinstance(request.get("context_overrides"), dict) else {}
    workflow_id = str(
        context_overrides.get("workflow_id")
        or request.get("workflow_id")
        or request.get("transition_name")
        or ""
    )

    is_blocked = decision_status.upper() in {"BLOCKED", "DENIED", "ERROR"}
    blocked_reason = reason_code if is_blocked and reason_code else None

    return {
        "tenant_id": effective_tenant,
        "decision_id": decision_id,
        "summary": evidence.get("summary"),
        "why_blocked": blocked_reason,
        "decision": {
            "status": decision_status,
            "reason_code": reason_code or None,
            "created_at": decision_row.get("created_at"),
            "repo": decision_row.get("repo"),
            "pr_number": decision_row.get("pr_number"),
            "jira_issue_id": request.get("issue_key"),
            "workflow_id": workflow_id or None,
            "transition_id": request.get("transition_id"),
            "actor": request.get("actor_account_id") or request.get("actor_id"),
            "environment": request.get("environment"),
            "project_key": request.get("project_key"),
        },
        "policy_binding": {
            "policy_id": primary_binding.get("policy_id") or binding.get("policy_id"),
            "policy_version": primary_binding.get("policy_version") or binding.get("snapshot_id"),
            "policy_hash": primary_binding.get("policy_hash") or binding.get("policy_hash") or decision_row.get("policy_hash"),
            "snapshot_hash": snapshot.get("policy_hash"),
            "binding_verified": bool(binding_verify.get("verified")),
            "binding": binding_verify,
        },
        "signals": signals,
        "risk_components": risk,
        "evaluation_tree": evidence.get("graph"),
        "evidence": evidence.get("evidence"),
        "replay": {"path": f"/decisions/{decision_id}/replay"},
    }
