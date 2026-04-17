"""Missing link enforcement rules for the Cross-System Governance Fabric.

Rules are configurable per-tenant via policy_overrides.  The defaults enforce
the strongest guarantees; tenants can relax rules by setting a rule to False.

Rule IDs (used in violation_codes and enforcement responses)
------------------------------------------------------------
PR_MISSING_JIRA         PR linked without a Jira issue
DEPLOY_MISSING_PR       Deployment recorded with no PR
DEPLOY_MISSING_DECISION Deployment recorded with no ReleaseGate decision ID
HOTFIX_MISSING_INCIDENT Hotfix started with no linked incident
INCIDENT_MISSING_DEPLOY Incident opened with no linked deployment
OVERRIDE_MISSING_REASON Override recorded without justification
ILLEGAL_TRANSITION      State machine transition would skip a required step
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


# Default rule set — all enforced
DEFAULT_RULES: Dict[str, bool] = {
    "pr_requires_jira":            True,
    "deploy_requires_pr":          True,
    "deploy_requires_decision":    True,
    "hotfix_requires_incident":    True,
    "incident_requires_deploy":    True,
    "override_requires_reason":    True,
}

# Maps rule names → violation codes + human messages
RULE_META: Dict[str, Dict[str, str]] = {
    "pr_requires_jira": {
        "code": "PR_MISSING_JIRA",
        "message": "PR is linked without a Jira issue. Every PR must map to a tracked ticket.",
    },
    "deploy_requires_pr": {
        "code": "DEPLOY_MISSING_PR",
        "message": "Deployment recorded with no linked PR. Orphan deploys are not permitted.",
    },
    "deploy_requires_decision": {
        "code": "DEPLOY_MISSING_DECISION",
        "message": "Deployment recorded with no ReleaseGate decision ID. Run POST /decisions/declare first.",
    },
    "hotfix_requires_incident": {
        "code": "HOTFIX_MISSING_INCIDENT",
        "message": "Hotfix started with no linked incident. Every hotfix must trace to an incident.",
    },
    "incident_requires_deploy": {
        "code": "INCIDENT_MISSING_DEPLOY",
        "message": "Incident opened with no linked deployment. Cannot determine root cause.",
    },
    "override_requires_reason": {
        "code": "OVERRIDE_MISSING_REASON",
        "message": "Override recorded without justification. All overrides require a documented reason.",
    },
}


def _resolve_rules(policy_overrides: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    rules = dict(DEFAULT_RULES)
    if policy_overrides:
        for key in DEFAULT_RULES:
            if key in policy_overrides:
                rules[key] = bool(policy_overrides[key])
    return rules


def evaluate_missing_links(
    *,
    record: Dict[str, Any],
    event: Optional[str] = None,
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    """Evaluate a ChangeRecord against all active missing-link rules.

    Returns a list of violation dicts: {code, rule, message}.
    An empty list means no violations.
    """
    rules = _resolve_rules(policy_overrides)
    violations: List[Dict[str, str]] = []

    def _has(field: str) -> bool:
        value = record.get(field)
        if field == "rg_decision_ids":
            if not value:
                return False
            try:
                ids = json.loads(value) if isinstance(value, str) else value
                return bool(ids)
            except Exception:
                return bool(str(value).strip())
        return bool(str(value or "").strip())

    # Rule: PR requires Jira
    if rules.get("pr_requires_jira") and _has("pr_repo") and not _has("jira_issue_key"):
        violations.append({**RULE_META["pr_requires_jira"], "rule": "pr_requires_jira"})

    # Rule: deploy requires PR
    if rules.get("deploy_requires_pr") and _has("deploy_id") and not _has("pr_repo"):
        violations.append({**RULE_META["deploy_requires_pr"], "rule": "deploy_requires_pr"})

    # Rule: deploy requires decision
    if rules.get("deploy_requires_decision") and _has("deploy_id") and not _has("rg_decision_ids"):
        violations.append({**RULE_META["deploy_requires_decision"], "rule": "deploy_requires_decision"})

    # Rule: hotfix requires incident
    if rules.get("hotfix_requires_incident") and _has("hotfix_id") and not _has("incident_id"):
        violations.append({**RULE_META["hotfix_requires_incident"], "rule": "hotfix_requires_incident"})

    # Rule: incident requires deploy
    if rules.get("incident_requires_deploy") and _has("incident_id") and not _has("deploy_id"):
        violations.append({**RULE_META["incident_requires_deploy"], "rule": "incident_requires_deploy"})

    return violations


def should_block(
    *,
    violations: List[Dict[str, str]],
    enforcement_mode: str = "STRICT",
) -> bool:
    """Return True if violations should block (STRICT mode), False if audit-only."""
    if not violations:
        return False
    return enforcement_mode.upper() == "STRICT"
