from __future__ import annotations

from typing import Any, Dict, List


def _collect_condition_deltas(diff_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    condition_deltas: List[Dict[str, Any]] = []
    for item in diff_report.get("rule_changes") or []:
        if not isinstance(item, dict):
            continue
        condition_deltas.append(
            {
                "rule": item.get("rule"),
                "change": item.get("change"),
                "from": item.get("from"),
                "to": item.get("to"),
            }
        )
    return condition_deltas


def _collect_role_deltas(diff_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    strictness = diff_report.get("strictness_delta") or {}
    roles = strictness.get("required_roles") if isinstance(strictness, dict) else {}
    if not isinstance(roles, dict):
        return []
    return [
        {
            "from": roles.get("from") or [],
            "to": roles.get("to") or [],
        }
    ]


def _collect_sod_deltas(diff_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    deltas: List[Dict[str, Any]] = []
    for signal in (diff_report.get("warnings") or []) + (diff_report.get("strengthening_signals") or []):
        if not isinstance(signal, dict):
            continue
        code = str(signal.get("code") or "")
        if "SOD" not in code and "ROLE" not in code:
            continue
        deltas.append(
            {
                "code": code,
                "message": signal.get("message"),
                "from": signal.get("from"),
                "to": signal.get("to"),
            }
        )
    return deltas


def build_policy_diff_visual(diff_report: Dict[str, Any]) -> Dict[str, Any]:
    strictness = diff_report.get("strictness_delta") if isinstance(diff_report.get("strictness_delta"), dict) else {}
    risk_threshold_changes = strictness.get("risk_threshold_changes") if isinstance(strictness, dict) else []
    threshold_deltas = risk_threshold_changes if isinstance(risk_threshold_changes, list) else []

    return {
        "report_id": diff_report.get("report_id"),
        "trace_id": diff_report.get("trace_id"),
        "tenant_id": diff_report.get("tenant_id"),
        "generated_at": diff_report.get("generated_at"),
        "overall": diff_report.get("overall"),
        "summary": diff_report.get("summary") or {},
        "active_policy": diff_report.get("current_policy") or {},
        "staged_policy": diff_report.get("candidate_policy") or {},
        "threshold_deltas": threshold_deltas,
        "condition_deltas": _collect_condition_deltas(diff_report),
        "role_deltas": _collect_role_deltas(diff_report),
        "sod_deltas": _collect_sod_deltas(diff_report),
        "warnings": diff_report.get("warnings") or [],
        "strengthening_signals": diff_report.get("strengthening_signals") or [],
    }
