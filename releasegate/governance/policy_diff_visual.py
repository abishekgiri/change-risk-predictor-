from __future__ import annotations

from typing import Any, Dict, List


_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _severity_for_threshold(change: Dict[str, Any]) -> str:
    direction = str(change.get("direction") or "").upper()
    if direction == "WEAKENING":
        return "high"
    if direction == "STRENGTHENING":
        return "low"
    return "medium"


def _extract_metric_from_path(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "unknown_metric"
    token = raw.split(".")[-1]
    return token or "unknown_metric"


def _collect_threshold_deltas(diff_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    strictness = diff_report.get("strictness_delta") or {}
    risk_changes = strictness.get("risk_threshold_changes") if isinstance(strictness, dict) else []
    if not isinstance(risk_changes, list):
        return []
    deltas: List[Dict[str, Any]] = []
    for item in risk_changes:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        deltas.append(
            {
                "metric": _extract_metric_from_path(path),
                "from": item.get("from"),
                "to": item.get("to"),
                "severity": _severity_for_threshold(item),
                "path": path or None,
            }
        )
    return deltas


def _severity_for_condition(change: str, old_result: str, new_result: str) -> str:
    if change == "REMOVED":
        return "medium"
    if change == "ADDED":
        return "low"
    if old_result == "BLOCK" and new_result != "BLOCK":
        return "high"
    if old_result != "BLOCK" and new_result == "BLOCK":
        return "low"
    return "medium"


def _normalize_rule_result(rule: Any) -> str:
    if not isinstance(rule, dict):
        return "UNKNOWN"
    result = str(rule.get("result") or rule.get("enforcement") or "").strip().lower()
    if result in {"block", "blocked", "deny", "denied"}:
        return "BLOCK"
    if result in {"warn", "conditional"}:
        return "WARN"
    if result in {"allow", "allowed"}:
        return "ALLOW"
    return "UNKNOWN"


def _collect_condition_deltas(diff_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    deltas: List[Dict[str, Any]] = []
    for item in diff_report.get("rule_changes") or []:
        if not isinstance(item, dict):
            continue
        raw_change = str(item.get("change") or "").strip().upper()
        op = "changed"
        if raw_change == "ADDED":
            op = "added"
        elif raw_change == "REMOVED":
            op = "removed"
        old_result = _normalize_rule_result(item.get("from"))
        new_result = _normalize_rule_result(item.get("to"))
        rule = str(item.get("rule") or "").strip()
        deltas.append(
            {
                "path": f"transition_rules.{rule}" if rule else None,
                "op": op,
                "from": item.get("from"),
                "to": item.get("to"),
                "severity": _severity_for_condition(raw_change, old_result, new_result),
            }
        )
    return deltas


def _collect_role_deltas(diff_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    strictness = diff_report.get("strictness_delta") or {}
    roles = strictness.get("required_roles") if isinstance(strictness, dict) else {}
    approvals = strictness.get("approvals_required") if isinstance(strictness, dict) else {}
    deltas: List[Dict[str, Any]] = []

    if isinstance(roles, dict):
        from_roles = {str(value).strip() for value in (roles.get("from") or []) if str(value).strip()}
        to_roles = {str(value).strip() for value in (roles.get("to") or []) if str(value).strip()}
        for role in sorted(from_roles - to_roles):
            deltas.append(
                {
                    "action": "approve",
                    "role": role,
                    "from": "required",
                    "to": "removed",
                    "severity": "high",
                    "path": f"approval_requirements.required_roles.{role}",
                }
            )
        for role in sorted(to_roles - from_roles):
            deltas.append(
                {
                    "action": "approve",
                    "role": role,
                    "from": "missing",
                    "to": "required",
                    "severity": "low",
                    "path": f"approval_requirements.required_roles.{role}",
                }
            )

    if isinstance(approvals, dict):
        from_count = int(approvals.get("from") or 0)
        to_count = int(approvals.get("to") or 0)
        if to_count != from_count:
            severity = "high" if to_count < from_count else "low"
            deltas.append(
                {
                    "action": "approve",
                    "role": "min_approvals",
                    "from": from_count,
                    "to": to_count,
                    "severity": severity,
                    "path": "approval_requirements.min_approvals",
                }
            )
    return deltas


def _severity_for_sod(code: str) -> str:
    upper = str(code or "").upper()
    if "WEAKEN" in upper:
        return "high"
    if "STRENGTHEN" in upper:
        return "low"
    return "medium"


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
                "scope": str(signal.get("scope") or "policy"),
                "from_roles": signal.get("from") if isinstance(signal.get("from"), list) else [],
                "to_roles": signal.get("to") if isinstance(signal.get("to"), list) else [],
                "severity": _severity_for_sod(code),
                "path": signal.get("path"),
            }
        )
    return deltas


def _sort_deltas(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity") or "medium").lower(), 1),
            str(item.get("path") or ""),
            str(item.get("metric") or item.get("role") or item.get("scope") or ""),
        ),
    )


def _severity_counts(*, groups: List[List[Dict[str, Any]]]) -> Dict[str, int]:
    counts = {"low": 0, "medium": 0, "high": 0}
    for group in groups:
        for item in group:
            severity = str(item.get("severity") or "").lower()
            if severity in counts:
                counts[severity] += 1
    return counts


def _summary_bullets(
    *,
    threshold_deltas: List[Dict[str, Any]],
    condition_deltas: List[Dict[str, Any]],
    role_deltas: List[Dict[str, Any]],
    sod_deltas: List[Dict[str, Any]],
) -> List[str]:
    bullets: List[str] = []
    for item in threshold_deltas:
        bullets.append(
            f"Updated threshold {item.get('metric')} from {item.get('from')} to {item.get('to')} ({str(item.get('severity') or '').upper()})."
        )
    for item in role_deltas:
        bullets.append(
            f"Role change for {item.get('role')}: {item.get('from')} -> {item.get('to')} ({str(item.get('severity') or '').upper()})."
        )
    for item in condition_deltas:
        bullets.append(
            f"Condition {item.get('op')} at {item.get('path')} ({str(item.get('severity') or '').upper()})."
        )
    for item in sod_deltas:
        bullets.append(
            f"SoD scope {item.get('scope')} changed ({str(item.get('severity') or '').upper()})."
        )
    ordered = sorted(
        bullets,
        key=lambda line: (
            0 if "(HIGH)" in line else 1 if "(MEDIUM)" in line else 2,
            line,
        ),
    )
    return ordered[:8]


def build_policy_diff_visual(diff_report: Dict[str, Any]) -> Dict[str, Any]:
    threshold_deltas = _sort_deltas(_collect_threshold_deltas(diff_report))
    condition_deltas = _sort_deltas(_collect_condition_deltas(diff_report))
    role_deltas = _sort_deltas(_collect_role_deltas(diff_report))
    sod_deltas = _sort_deltas(_collect_sod_deltas(diff_report))
    change_count = len(threshold_deltas) + len(condition_deltas) + len(role_deltas) + len(sod_deltas)
    severity_counts = _severity_counts(
        groups=[threshold_deltas, condition_deltas, role_deltas, sod_deltas],
    )
    summary_bullets = _summary_bullets(
        threshold_deltas=threshold_deltas,
        condition_deltas=condition_deltas,
        role_deltas=role_deltas,
        sod_deltas=sod_deltas,
    )
    legacy_summary = diff_report.get("summary") if isinstance(diff_report.get("summary"), dict) else {}

    return {
        "report_id": diff_report.get("report_id"),
        "trace_id": diff_report.get("trace_id"),
        "tenant_id": diff_report.get("tenant_id"),
        "generated_at": diff_report.get("generated_at"),
        "overall": diff_report.get("overall"),
        "summary": {
            "has_changes": bool(change_count),
            "change_count": int(change_count),
            "severity_counts": severity_counts,
            "summary_bullets": summary_bullets,
            "warning_count": int(legacy_summary.get("warning_count") or len(diff_report.get("warnings") or [])),
            "strengthening_count": int(
                legacy_summary.get("strengthening_count") or len(diff_report.get("strengthening_signals") or [])
            ),
            "rule_change_count": int(legacy_summary.get("rule_change_count") or len(diff_report.get("rule_changes") or [])),
            "risk_threshold_change_count": int(
                legacy_summary.get("risk_threshold_change_count")
                or len((diff_report.get("strictness_delta") or {}).get("risk_threshold_changes") or [])
            ),
        },
        "active_policy": diff_report.get("current_policy") or {},
        "staged_policy": diff_report.get("candidate_policy") or {},
        "threshold_deltas": threshold_deltas,
        "condition_deltas": condition_deltas,
        "role_deltas": role_deltas,
        "sod_deltas": sod_deltas,
        "warnings": diff_report.get("warnings") or [],
        "strengthening_signals": diff_report.get("strengthening_signals") or [],
        "legacy_summary": legacy_summary,
    }
