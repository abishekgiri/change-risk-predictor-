from __future__ import annotations

from typing import Any, Dict, List

from releasegate.policy.lint import lint_registry_policy


_HARD_CONFLICT_CODES = {
    "CONTRADICTORY_RULES",
    "OVERLAPPING_RULES",
    "AMBIGUOUS_OVERLAP",
    "RULE_INVALID_LOGIC",
    "APPROVAL_REQUIREMENT_IMPOSSIBLE",
}

_SHADOW_CODES = {"RULE_UNREACHABLE_SHADOWED"}
_COVERAGE_CODES = {"RULE_NO_COVERAGE", "TRANSITION_UNCOVERED", "COVERAGE_GAP"}


def analyze_policy_conflicts(policy_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce a formalized conflict report for activation/simulation control-plane APIs.
    Uses registry lint output and groups findings into governance categories.
    """
    report = lint_registry_policy(policy_json)
    issues = report.get("issues") if isinstance(report.get("issues"), list) else []

    contradictions: List[Dict[str, Any]] = []
    shadowed_rules: List[Dict[str, Any]] = []
    coverage_gaps: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    for issue in issues:
        if not isinstance(issue, dict):
            continue
        code = str(issue.get("code") or "").strip().upper()
        severity = str(issue.get("severity") or "").strip().upper()

        if code in _HARD_CONFLICT_CODES:
            contradictions.append(issue)
            continue
        if code in _SHADOW_CODES:
            shadowed_rules.append(issue)
            continue
        if code in _COVERAGE_CODES:
            coverage_gaps.append(issue)
            continue
        if severity == "WARNING":
            warnings.append(issue)

    return {
        "ok": len(contradictions) == 0,
        "contradictions": contradictions,
        "shadowed_rules": shadowed_rules,
        "coverage_gaps": coverage_gaps,
        "warnings": warnings,
        "summary": {
            "contradiction_count": len(contradictions),
            "shadowed_rule_count": len(shadowed_rules),
            "coverage_gap_count": len(coverage_gaps),
            "warning_count": len(warnings),
        },
        "lint": {
            "ok": bool(report.get("ok")),
            "error_count": int(report.get("error_count") or 0),
            "warning_count": int(report.get("warning_count") or 0),
        },
    }


def hard_conflicts(policy_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_policy_conflicts(policy_json).get("contradictions", [])
