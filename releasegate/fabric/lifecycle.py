"""Lifecycle state machine for ChangeRecord.

States
------
CREATED            → change opened, no system links yet
LINKED             → PR and/or Jira attached
APPROVED           → ReleaseGate decision ALLOWED, all required approvals present
DEPLOYED           → deploy_id recorded
INCIDENT_ACTIVE    → an incident was opened against this change's deploy
HOTFIX_IN_PROGRESS → a hotfix deploy is underway to resolve the incident
VERIFIED           → post-deploy checks passed (or hotfix resolved incident)
CLOSED             → change complete; immutable
BLOCKED            → enforcement violation detected in STRICT mode

Allowed transitions
-------------------
CREATED            → LINKED, BLOCKED
LINKED             → APPROVED, BLOCKED
APPROVED           → DEPLOYED, BLOCKED
DEPLOYED           → VERIFIED, INCIDENT_ACTIVE, BLOCKED
INCIDENT_ACTIVE    → HOTFIX_IN_PROGRESS, BLOCKED
HOTFIX_IN_PROGRESS → VERIFIED, BLOCKED
VERIFIED           → CLOSED
BLOCKED            → LINKED, APPROVED  (recovery — fix links, re-evaluate)

Any state → BLOCKED is always legal (enforcement can block at any point).
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set

# All valid states
STATES: Set[str] = {
    "CREATED",
    "LINKED",
    "APPROVED",
    "DEPLOYED",
    "INCIDENT_ACTIVE",
    "HOTFIX_IN_PROGRESS",
    "VERIFIED",
    "CLOSED",
    "BLOCKED",
}

# Allowed forward transitions (from_state → set of valid to_states)
TRANSITIONS: Dict[str, Set[str]] = {
    "CREATED":            {"LINKED", "BLOCKED"},
    "LINKED":             {"APPROVED", "BLOCKED"},
    "APPROVED":           {"DEPLOYED", "BLOCKED"},
    "DEPLOYED":           {"VERIFIED", "INCIDENT_ACTIVE", "BLOCKED"},
    "INCIDENT_ACTIVE":    {"HOTFIX_IN_PROGRESS", "BLOCKED"},
    "HOTFIX_IN_PROGRESS": {"VERIFIED", "BLOCKED"},
    "VERIFIED":           {"CLOSED"},
    "CLOSED":             set(),                        # terminal
    "BLOCKED":            {"LINKED", "APPROVED"},       # recovery only
}

# Links required to be present before entering each state
REQUIRED_LINKS_FOR_STATE: Dict[str, List[str]] = {
    "APPROVED":  ["jira_issue_key", "rg_decision_ids"],
    "DEPLOYED":  ["jira_issue_key", "pr_repo", "rg_decision_ids", "deploy_id"],
    "VERIFIED":  ["jira_issue_key", "pr_repo", "rg_decision_ids", "deploy_id"],
    "CLOSED":    ["jira_issue_key", "pr_repo", "rg_decision_ids", "deploy_id"],
}

# Hotfix must have an incident
HOTFIX_REQUIRED_LINKS: List[str] = ["incident_id"]


def validate_transition(
    *,
    current_state: str,
    target_state: str,
) -> Optional[str]:
    """Return an error string if the transition is illegal, else None."""
    if current_state not in STATES:
        return f"Unknown current state: {current_state}"
    if target_state not in STATES:
        return f"Unknown target state: {target_state}"
    allowed = TRANSITIONS.get(current_state, set())
    if target_state not in allowed:
        return (
            f"Illegal transition {current_state} → {target_state}. "
            f"Allowed: {sorted(allowed) or 'none (terminal state)'}"
        )
    return None


def check_required_links(
    *,
    target_state: str,
    record: Dict,
    is_hotfix: bool = False,
) -> List[str]:
    """Return list of missing link field names for the target state."""
    import json

    missing: List[str] = []
    required = list(REQUIRED_LINKS_FOR_STATE.get(target_state, []))

    if is_hotfix or target_state in ("HOTFIX_IN_PROGRESS", "VERIFIED") and record.get("hotfix_id"):
        required = list(set(required) | set(HOTFIX_REQUIRED_LINKS))

    for field in required:
        value = record.get(field)
        if field == "rg_decision_ids":
            # Accept either a populated JSON list or a non-empty string
            if not value:
                missing.append(field)
                continue
            try:
                ids = json.loads(value) if isinstance(value, str) else value
                if not ids:
                    missing.append(field)
            except Exception:
                if not str(value).strip():
                    missing.append(field)
        else:
            if not str(value or "").strip():
                missing.append(field)
    return missing


def next_state_for_event(event: str, current_state: str) -> Optional[str]:
    """Map a domain event to the next lifecycle state."""
    EVENT_MAP: Dict[str, Dict[str, str]] = {
        "pr_linked":       {"CREATED": "LINKED", "BLOCKED": "LINKED"},
        "jira_linked":     {"CREATED": "LINKED", "BLOCKED": "LINKED"},
        "decision_allowed": {"LINKED": "APPROVED"},
        "deployed":        {"APPROVED": "DEPLOYED"},
        "incident_opened": {"DEPLOYED": "INCIDENT_ACTIVE"},
        "hotfix_started":  {"INCIDENT_ACTIVE": "HOTFIX_IN_PROGRESS"},
        "verified":        {"DEPLOYED": "VERIFIED", "HOTFIX_IN_PROGRESS": "VERIFIED"},
        "closed":          {"VERIFIED": "CLOSED"},
        "violation":       {s: "BLOCKED" for s in STATES if s != "CLOSED"},
    }
    return EVENT_MAP.get(event, {}).get(current_state)
