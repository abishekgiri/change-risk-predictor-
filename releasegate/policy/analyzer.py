from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _norm_lower(value: Any) -> str:
    return _norm(value).lower()


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _risk_matches_condition(conditions: Dict[str, Any], risk_band: str) -> bool:
    if not conditions:
        return True
    risk_value = risk_band.strip().lower()
    candidates: List[Any] = []
    for key in ("risk", "risk_band", "risk_level", "core_risk.severity_level"):
        if key in conditions:
            candidates.append(conditions.get(key))
    if not candidates:
        return True

    for candidate in candidates:
        if isinstance(candidate, str):
            if candidate.strip().lower() == risk_value:
                return True
            continue
        if isinstance(candidate, list):
            normalized = {str(item).strip().lower() for item in candidate if str(item).strip()}
            if risk_value in normalized:
                return True
            continue
        if isinstance(candidate, dict):
            eq_value = candidate.get("eq")
            if eq_value is not None and str(eq_value).strip().lower() == risk_value:
                return True
            in_values = candidate.get("in")
            if isinstance(in_values, list):
                normalized = {str(item).strip().lower() for item in in_values if str(item).strip()}
                if risk_value in normalized:
                    return True
    return False


def _rule_matches_target(
    rule: Dict[str, Any],
    *,
    transition_id: str,
    environment: str,
    project_id: str,
    workflow_id: str,
    risk_band: str,
) -> bool:
    if _norm(rule.get("transition_id")) not in {"", transition_id}:
        return False
    if environment and _norm_lower(rule.get("environment")) not in {"", environment.lower()}:
        return False
    if project_id and _norm(rule.get("project_id")) not in {"", project_id}:
        return False
    if workflow_id and _norm(rule.get("workflow_id")) not in {"", workflow_id}:
        return False
    conditions = _as_dict(rule.get("conditions"))
    return _risk_matches_condition(conditions, risk_band)


def _target_envs(targets: Sequence[Dict[str, Any]], transition_rules: Sequence[Dict[str, Any]]) -> List[str]:
    envs = {
        _norm_lower(target.get("environment") or target.get("env"))
        for target in targets
        if _norm(target.get("environment") or target.get("env"))
    }
    if envs:
        return sorted(envs)
    derived = {
        _norm_lower(rule.get("environment"))
        for rule in transition_rules
        if _norm(rule.get("environment"))
    }
    return sorted(derived) if derived else ["prod"]


def detect_transition_coverage(policy_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = policy_json if isinstance(policy_json, dict) else {}
    required_raw = _as_list(payload.get("required_transitions"))
    transition_rules = [rule for rule in _as_list(payload.get("transition_rules")) if isinstance(rule, dict)]
    if not required_raw:
        return []

    targets: List[Dict[str, Any]] = []
    for item in required_raw:
        if isinstance(item, dict):
            transition_id = _norm(item.get("transition_id") or item.get("transition"))
            if not transition_id:
                continue
            targets.append(
                {
                    "transition_id": transition_id,
                    "environment": _norm(item.get("environment") or item.get("env")),
                    "project_id": _norm(item.get("project_id")),
                    "workflow_id": _norm(item.get("workflow_id")),
                }
            )
            continue
        transition_id = _norm(item)
        if transition_id:
            targets.append({"transition_id": transition_id, "environment": "", "project_id": "", "workflow_id": ""})

    if not targets:
        return []

    risk_bands = ["LOW", "MEDIUM", "HIGH"]
    default_envs = _target_envs(targets, transition_rules)
    issues: List[Dict[str, Any]] = []
    for target in targets:
        transition_id = _norm(target.get("transition_id"))
        envs = [target["environment"]] if _norm(target.get("environment")) else default_envs
        for environment in envs:
            for risk_band in risk_bands:
                if any(
                    _rule_matches_target(
                        rule,
                        transition_id=transition_id,
                        environment=environment,
                        project_id=_norm(target.get("project_id")),
                        workflow_id=_norm(target.get("workflow_id")),
                        risk_band=risk_band,
                    )
                    for rule in transition_rules
                ):
                    continue
                issues.append(
                    {
                        "severity": "ERROR",
                        "code": "RULE_NO_COVERAGE",
                        "message": (
                            f"No transition rule covers transition `{transition_id}` for environment "
                            f"`{environment}` and risk `{risk_band}`."
                        ),
                        "metadata": {
                            "transition_id": transition_id,
                            "environment": environment,
                            "risk_band": risk_band,
                            "project_id": _norm(target.get("project_id")),
                            "workflow_id": _norm(target.get("workflow_id")),
                        },
                    }
                )
    return issues

