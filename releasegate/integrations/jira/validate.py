from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set

from releasegate.integrations.jira.client import JiraClient, JiraClientError
from releasegate.integrations.jira.config import (
    JiraConfigIssue,
    JiraRoleMap,
    JiraTransitionMap,
    load_compiled_policy_ids,
    load_role_map,
    load_transition_map,
    validate_jira_maps,
)


def _collect_project_keys(transition_map: JiraTransitionMap) -> List[str]:
    project_keys: Set[str] = {project_key.upper() for project_key in transition_map.jira.project_keys}
    for rule in transition_map.transitions:
        for project_key in rule.project_keys:
            cleaned = str(project_key).strip().upper()
            if cleaned:
                project_keys.add(cleaned)
    return sorted(project_keys)


def _collect_transition_ids(transition_map: JiraTransitionMap) -> List[str]:
    ids = set()
    for rule in transition_map.transitions:
        if rule.transition_id:
            ids.add(str(rule.transition_id).strip())
    return sorted(ids)


def _connectivity_warnings(
    *,
    transition_map: JiraTransitionMap,
    role_map: JiraRoleMap,
    jira_client: JiraClient,
) -> List[JiraConfigIssue]:
    warnings: List[JiraConfigIssue] = []

    if not jira_client.check_permissions():
        warnings.append(
            JiraConfigIssue(
                severity="WARN",
                code="JIRA_CONNECTIVITY_UNAVAILABLE",
                message="Jira connectivity check skipped because credentials are unavailable or invalid.",
                location="jira_connectivity",
            )
        )
        return warnings

    project_keys = _collect_project_keys(transition_map)
    transition_ids = set(_collect_transition_ids(transition_map))
    jira_transition_ids: Set[str] = set()

    for project_key in project_keys:
        try:
            jira_transition_ids.update(jira_client.list_transition_ids(project_key))
        except JiraClientError as exc:
            warnings.append(
                JiraConfigIssue(
                    severity="WARN",
                    code="JIRA_TRANSITIONS_LOOKUP_FAILED",
                    message=f"Unable to fetch transition IDs for project `{project_key}`: {exc}",
                    location=f"project:{project_key}",
                )
            )

    unknown_transition_ids = sorted(transition_ids - jira_transition_ids) if jira_transition_ids else []
    for transition_id in unknown_transition_ids:
        warnings.append(
            JiraConfigIssue(
                severity="WARN",
                code="JIRA_TRANSITION_ID_UNKNOWN",
                message=f"Configured transition_id `{transition_id}` was not found in Jira transition metadata.",
                location=f"transition_id:{transition_id}",
            )
        )

    try:
        jira_groups = {group.lower() for group in jira_client.list_group_names()}
    except JiraClientError as exc:
        warnings.append(
            JiraConfigIssue(
                severity="WARN",
                code="JIRA_GROUP_LOOKUP_FAILED",
                message=f"Unable to fetch Jira groups: {exc}",
                location="jira_groups",
            )
        )
        jira_groups = set()

    jira_project_roles: Set[str] = set()
    for project_key in project_keys:
        try:
            jira_project_roles.update(role.lower() for role in jira_client.list_project_role_names(project_key))
        except JiraClientError as exc:
            warnings.append(
                JiraConfigIssue(
                    severity="WARN",
                    code="JIRA_PROJECT_ROLE_LOOKUP_FAILED",
                    message=f"Unable to fetch project roles for `{project_key}`: {exc}",
                    location=f"project:{project_key}",
                )
            )

    for role_name, resolver in role_map.roles.items():
        for group_name in resolver.jira_groups:
            if jira_groups and group_name.lower() not in jira_groups:
                warnings.append(
                    JiraConfigIssue(
                        severity="WARN",
                        code="JIRA_GROUP_UNKNOWN",
                        message=f"Role `{role_name}` references unknown Jira group `{group_name}`.",
                        location=f"role:{role_name}",
                    )
                )
        for project_role in resolver.jira_project_roles:
            if jira_project_roles and project_role.lower() not in jira_project_roles:
                warnings.append(
                    JiraConfigIssue(
                        severity="WARN",
                        code="JIRA_PROJECT_ROLE_UNKNOWN",
                        message=f"Role `{role_name}` references unknown Jira project role `{project_role}`.",
                        location=f"role:{role_name}",
                    )
                )

    return warnings


def validate_jira_config_files(
    *,
    transition_map_path: str,
    role_map_path: str,
    policy_dir: str = "releasegate/policy/compiled",
    check_jira: bool = False,
    jira_client: Optional[JiraClient] = None,
) -> Dict[str, Any]:
    issues: List[JiraConfigIssue] = []

    try:
        transition_map = load_transition_map(transition_map_path)
    except Exception as exc:
        issues.append(
            JiraConfigIssue(
                severity="ERROR",
                code="TRANSITION_MAP_INVALID",
                message=str(exc),
                location=transition_map_path,
            )
        )
        transition_map = None

    try:
        role_map = load_role_map(role_map_path)
    except Exception as exc:
        issues.append(
            JiraConfigIssue(
                severity="ERROR",
                code="ROLE_MAP_INVALID",
                message=str(exc),
                location=role_map_path,
            )
        )
        role_map = None

    known_policy_ids = load_compiled_policy_ids(policy_dir=policy_dir)

    if transition_map and role_map:
        base = validate_jira_maps(
            transition_map=transition_map,
            role_map=role_map,
            known_policy_ids=known_policy_ids,
        )
        for issue in base.get("issues", []):
            issues.append(
                JiraConfigIssue(
                    severity=issue.get("severity", "ERROR"),
                    code=issue.get("code", "UNKNOWN"),
                    message=issue.get("message", ""),
                    location=issue.get("location"),
                )
            )
        if check_jira:
            client = jira_client or JiraClient()
            issues.extend(
                _connectivity_warnings(
                    transition_map=transition_map,
                    role_map=role_map,
                    jira_client=client,
                )
            )

    errors = [issue.as_dict() for issue in issues if issue.severity == "ERROR"]
    warnings = [issue.as_dict() for issue in issues if issue.severity == "WARN"]
    status = "FAIL" if errors else ("WARN" if warnings else "OK")
    return {
        "status": status,
        "ok": not errors,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "issues": [issue.as_dict() for issue in issues],
        "known_policy_count": len(known_policy_ids),
        "transition_map_path": transition_map_path,
        "role_map_path": role_map_path,
    }


def format_jira_validation_report(report: Dict[str, Any]) -> str:
    lines = [
        f"Jira Config Validation: {report.get('status', 'FAIL')}",
        f"Transition Map: {report.get('transition_map_path')}",
        f"Role Map: {report.get('role_map_path')}",
        f"Known Policies: {report.get('known_policy_count', 0)}",
        f"Errors: {report.get('error_count', 0)}",
        f"Warnings: {report.get('warning_count', 0)}",
    ]
    issues = report.get("issues") or []
    if issues:
        lines.append("")
        lines.append("Issues:")
        for issue in issues:
            location = f" ({issue['location']})" if issue.get("location") else ""
            lines.append(
                f"- [{issue.get('severity')}] {issue.get('code')}: {issue.get('message')}{location}"
            )
    return "\n".join(lines)
