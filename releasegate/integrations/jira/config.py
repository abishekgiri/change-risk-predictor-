from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from releasegate.policy.loader import PolicyLoader
from releasegate.policy.policy_types import Policy


ALLOWED_RELEASEGATE_ROLES = {"admin", "operator", "auditor", "read_only"}


class JiraScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_keys: List[str] = Field(default_factory=list)
    issue_types: List[str] = Field(default_factory=list)


class JiraTransitionAppliesTo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    branches: List[str] = Field(default_factory=list)
    environments: List[str] = Field(default_factory=list)


class JiraTransitionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transition_id: Optional[str] = None
    transition_name: Optional[str] = None
    gate: str
    mode: Optional[Literal["strict", "permissive"]] = None
    applies_to: JiraTransitionAppliesTo = Field(default_factory=JiraTransitionAppliesTo)
    project_keys: List[str] = Field(default_factory=list)
    issue_types: List[str] = Field(default_factory=list)

    @field_validator("transition_id", "transition_name", "gate")
    @classmethod
    def _strip_strings(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("project_keys", "issue_types")
    @classmethod
    def _normalize_list(cls, value: Sequence[str]) -> List[str]:
        return [str(item).strip() for item in value if str(item).strip()]

    @model_validator(mode="after")
    def _require_transition_identity(self) -> "JiraTransitionRule":
        if not self.transition_id and not self.transition_name:
            raise ValueError("transition rule must include transition_id or transition_name")
        return self


class JiraTransitionMap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    jira: JiraScopeConfig = Field(default_factory=JiraScopeConfig)
    gate_bindings: Dict[str, List[str]] = Field(default_factory=dict)
    transitions: List[JiraTransitionRule]

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("supported Jira transition map version is 1")
        return value

    @field_validator("gate_bindings")
    @classmethod
    def _validate_gate_bindings(cls, value: Dict[str, List[str]]) -> Dict[str, List[str]]:
        normalized: Dict[str, List[str]] = {}
        for gate_name, policy_ids in value.items():
            gate = str(gate_name).strip()
            if not gate:
                raise ValueError("gate_bindings contains an empty gate key")
            if not isinstance(policy_ids, list) or not policy_ids:
                raise ValueError(f"gate `{gate}` must map to a non-empty policy-id list")
            normalized[gate] = [str(pid).strip() for pid in policy_ids if str(pid).strip()]
            if not normalized[gate]:
                raise ValueError(f"gate `{gate}` resolved to an empty policy-id list")
        return normalized


class JiraRoleResolver(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jira_groups: List[str] = Field(default_factory=list)
    jira_project_roles: List[str] = Field(default_factory=list)

    @field_validator("jira_groups", "jira_project_roles")
    @classmethod
    def _normalize_list(cls, value: Sequence[str]) -> List[str]:
        return [str(item).strip() for item in value if str(item).strip()]

    @model_validator(mode="after")
    def _require_one_resolver(self) -> "JiraRoleResolver":
        if not self.jira_groups and not self.jira_project_roles:
            raise ValueError("role resolver must include jira_groups or jira_project_roles")
        return self


class JiraRoleMap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    roles: Dict[str, JiraRoleResolver]

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("supported Jira role map version is 1")
        return value

    @field_validator("roles")
    @classmethod
    def _validate_role_names(cls, value: Dict[str, JiraRoleResolver]) -> Dict[str, JiraRoleResolver]:
        invalid = sorted(set(value.keys()) - ALLOWED_RELEASEGATE_ROLES)
        if invalid:
            raise ValueError(
                "role map contains unsupported role keys: "
                + ", ".join(invalid)
                + f" (allowed: {', '.join(sorted(ALLOWED_RELEASEGATE_ROLES))})"
            )
        return value


@dataclass
class JiraConfigIssue:
    severity: Literal["ERROR", "WARN"]
    code: str
    message: str
    location: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        payload = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.location:
            payload["location"] = self.location
        return payload


def _load_yaml_file(path: str) -> Dict[str, Any]:
    loaded_path = Path(path)
    if not loaded_path.exists():
        raise FileNotFoundError(f"file not found: {path}")
    with loaded_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"expected a YAML object at top-level in {path}")
    return data


def load_transition_map(path: str) -> JiraTransitionMap:
    data = _load_yaml_file(path)
    try:
        return JiraTransitionMap.model_validate(data)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def load_role_map(path: str) -> JiraRoleMap:
    data = _load_yaml_file(path)
    try:
        return JiraRoleMap.model_validate(data)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def load_compiled_policy_ids(policy_dir: str = "releasegate/policy/compiled") -> List[str]:
    loader = PolicyLoader(policy_dir=policy_dir, schema="compiled", strict=False)
    try:
        loaded = loader.load_all()
    except Exception:
        return []
    return sorted({p.policy_id for p in loaded if isinstance(p, Policy)})


def resolve_gate_policy_ids(
    transition_map: JiraTransitionMap,
    gate_name: str,
    known_policy_ids: Iterable[str],
) -> Tuple[List[str], Optional[str]]:
    gate = str(gate_name).strip()
    if not gate:
        return [], "empty gate name"
    if gate in transition_map.gate_bindings:
        return list(transition_map.gate_bindings[gate]), None
    policy_id_set = set(known_policy_ids)
    if gate in policy_id_set:
        return [gate], None
    return [], f"gate `{gate}` is not a known policy_id and is not present in gate_bindings"


def validate_jira_maps(
    *,
    transition_map: JiraTransitionMap,
    role_map: JiraRoleMap,
    known_policy_ids: Sequence[str],
) -> Dict[str, Any]:
    issues: List[JiraConfigIssue] = []
    policy_id_set = set(known_policy_ids)

    if transition_map.jira.project_keys:
        unknown_project_entries = [pk for pk in transition_map.jira.project_keys if not pk.strip()]
        if unknown_project_entries:
            issues.append(
                JiraConfigIssue(
                    severity="ERROR",
                    code="TRANSITION_PROJECT_KEYS_INVALID",
                    message="jira.project_keys must not contain empty values.",
                    location="transition_map.jira.project_keys",
                )
            )

    duplicate_guard: set[Tuple[str, str, str, str]] = set()
    for idx, rule in enumerate(transition_map.transitions):
        location = f"transition_map.transitions[{idx}]"
        transition_key = ("id", rule.transition_id) if rule.transition_id else ("name", (rule.transition_name or "").lower())
        scope_projects = rule.project_keys or transition_map.jira.project_keys or ["*"]
        scope_issue_types = rule.issue_types or transition_map.jira.issue_types or ["*"]

        if not scope_projects:
            scope_projects = ["*"]
        if not scope_issue_types:
            scope_issue_types = ["*"]

        for project_key in scope_projects:
            for issue_type in scope_issue_types:
                unique_key = (
                    project_key.upper(),
                    issue_type.lower(),
                    transition_key[0],
                    str(transition_key[1]).lower(),
                )
                if unique_key in duplicate_guard:
                    issues.append(
                        JiraConfigIssue(
                            severity="ERROR",
                            code="TRANSITION_RULE_DUPLICATE",
                            message=(
                                "duplicate transition mapping after scope expansion for "
                                f"project={project_key}, issue_type={issue_type}, {transition_key[0]}={transition_key[1]}"
                            ),
                            location=location,
                        )
                    )
                duplicate_guard.add(unique_key)

        resolved_policy_ids, gate_error = resolve_gate_policy_ids(
            transition_map=transition_map,
            gate_name=rule.gate,
            known_policy_ids=policy_id_set,
        )
        if gate_error:
            issues.append(
                JiraConfigIssue(
                    severity="ERROR",
                    code="TRANSITION_GATE_UNKNOWN",
                    message=gate_error,
                    location=location,
                )
            )
            continue
        unknown_policy_refs = sorted(set(resolved_policy_ids) - policy_id_set)
        if unknown_policy_refs:
            issues.append(
                JiraConfigIssue(
                    severity="ERROR",
                    code="TRANSITION_GATE_POLICY_UNKNOWN",
                    message="gate resolves to unknown policy IDs: " + ", ".join(unknown_policy_refs),
                    location=location,
                )
            )

    if not role_map.roles:
        issues.append(
            JiraConfigIssue(
                severity="ERROR",
                code="ROLE_MAP_EMPTY",
                message="role map must define at least one role resolver.",
                location="role_map.roles",
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
        "known_policy_count": len(policy_id_set),
        "transition_count": len(transition_map.transitions),
        "role_count": len(role_map.roles),
    }
