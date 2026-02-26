from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import yaml

from releasegate.policy.loader import PolicyLoader
from releasegate.policy.policy_types import Policy
from releasegate.utils.paths import safe_join_under


def _issue(
    severity: str,
    code: str,
    message: str,
    *,
    policy_id: Optional[str] = None,
    source_file: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    issue = {
        "severity": severity,
        "code": code,
        "message": message,
    }
    if policy_id:
        issue["policy_id"] = policy_id
    if source_file:
        issue["source_file"] = source_file
    if metadata:
        issue["metadata"] = metadata
    return issue


def _iter_policy_yaml(policy_dir: str, *, base_dir: Optional[Union[str, Path]] = None) -> List[Tuple[str, Dict[str, Any]]]:
    docs: List[Tuple[str, Dict[str, Any]]] = []
    policy_dir_norm = str(policy_dir).replace("\\", "/").strip()
    if Path(policy_dir_norm).is_absolute():
        return docs

    policy_base = safe_join_under(base_dir or Path.cwd(), policy_dir_norm)
    if not policy_base.exists():
        return docs
    for root, _, files in os.walk(policy_base):
        root_path = Path(root)
        for file_name in sorted(files):
            if file_name.startswith("_") or not file_name.endswith((".yaml", ".yml")):
                continue
            try:
                rel_root = root_path.relative_to(policy_base)
                full_path = safe_join_under(policy_base, rel_root, file_name)
            except ValueError:
                continue
            with full_path.open("r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle) or {}
            if isinstance(loaded, dict):
                docs.append((str(full_path), loaded))
    return docs


def _is_number(value: Any) -> bool:
    try:
        float(value)
        return True
    except Exception:
        return False


def _control_signature(control: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(control.get("signal")),
        str(control.get("operator")),
        json.dumps(control.get("value"), sort_keys=True, separators=(",", ":")),
    )


def _controls_for_policy(policy: Policy) -> List[Dict[str, Any]]:
    return [control.model_dump(mode="json") for control in policy.controls]


def _policy_priority(policy: Policy) -> int:
    metadata = policy.metadata or {}
    raw = metadata.get("priority", 1000)
    try:
        return int(raw)
    except Exception:
        return 1000


def _check_contradictions_for_controls(controls: Sequence[Dict[str, Any]]) -> List[Tuple[str, str]]:
    issues: List[Tuple[str, str]] = []
    by_signal: Dict[str, List[Dict[str, Any]]] = {}
    for ctrl in controls:
        signal = str(ctrl.get("signal"))
        if not signal:
            continue
        by_signal.setdefault(signal, []).append(ctrl)

    for signal, entries in by_signal.items():
        equals = [c.get("value") for c in entries if c.get("operator") == "=="]
        not_equals = [c.get("value") for c in entries if c.get("operator") == "!="]
        in_values = [c.get("value") for c in entries if c.get("operator") == "in" and isinstance(c.get("value"), list)]
        not_in_values = [c.get("value") for c in entries if c.get("operator") == "not in" and isinstance(c.get("value"), list)]

        if len({json.dumps(v, sort_keys=True, separators=(",", ":")) for v in equals}) > 1:
            issues.append(("CONTRADICTORY_EQUALITY", f"Signal `{signal}` has multiple incompatible equality constraints."))
        for eq_val in equals:
            if any(eq_val == ne for ne in not_equals):
                issues.append(
                    ("CONTRADICTORY_EQUALITY_NEGATION", f"Signal `{signal}` requires and forbids the same value `{eq_val}`.")
                )
                break

        if in_values and not_in_values:
            combined_in = set().union(*[set(v) for v in in_values])
            combined_not_in = set().union(*[set(v) for v in not_in_values])
            if combined_in and combined_in.issubset(combined_not_in):
                issues.append(("CONTRADICTORY_IN_NOT_IN", f"Signal `{signal}` `in` values are fully excluded by `not in`."))

        lower_value: Optional[float] = None
        lower_inclusive = True
        upper_value: Optional[float] = None
        upper_inclusive = True
        has_numeric_bounds = False

        for c in entries:
            op = c.get("operator")
            value = c.get("value")
            if op not in {">", ">=", "<", "<="} or not _is_number(value):
                continue
            has_numeric_bounds = True
            v = float(value)
            if op in {">", ">="}:
                inclusive = op == ">="
                if lower_value is None or v > lower_value or (v == lower_value and not inclusive and lower_inclusive):
                    lower_value = v
                    lower_inclusive = inclusive
            else:
                inclusive = op == "<="
                if upper_value is None or v < upper_value or (v == upper_value and not inclusive and upper_inclusive):
                    upper_value = v
                    upper_inclusive = inclusive

        if has_numeric_bounds and lower_value is not None and upper_value is not None:
            if lower_value > upper_value or (lower_value == upper_value and (not lower_inclusive or not upper_inclusive)):
                issues.append(("CONTRADICTORY_NUMERIC_BOUNDS", f"Signal `{signal}` has mutually exclusive numeric bounds."))

    return issues


def _check_internal_contradictions(policy: Policy, source_file: Optional[str]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    controls = _controls_for_policy(policy)
    for code, message in _check_contradictions_for_controls(controls):
        issues.append(
            _issue(
                "ERROR",
                code,
                message,
                policy_id=policy.policy_id,
                source_file=source_file,
            )
        )
    return issues


def _controls_overlap(a_controls: Sequence[Dict[str, Any]], b_controls: Sequence[Dict[str, Any]]) -> bool:
    signals_a = {str(control.get("signal")) for control in a_controls if str(control.get("signal"))}
    signals_b = {str(control.get("signal")) for control in b_controls if str(control.get("signal"))}
    if not signals_a.intersection(signals_b):
        # Without at least one shared signal we cannot prove overlap structurally.
        return False

    # If merged constraints are contradictory, there is no overlapping match space.
    merged = list(a_controls) + list(b_controls)
    return not _check_contradictions_for_controls(merged)


def _is_broader_or_equal_controls(
    broader_controls: Sequence[Dict[str, Any]],
    narrower_controls: Sequence[Dict[str, Any]],
) -> bool:
    broader_signatures = {_control_signature(control) for control in broader_controls}
    narrower_signatures = {_control_signature(control) for control in narrower_controls}
    return broader_signatures.issubset(narrower_signatures)


def _extract_risk_bands(policy: Policy) -> List[str]:
    bands: set[str] = set()
    for control in _controls_for_policy(policy):
        signal = str(control.get("signal"))
        op = str(control.get("operator"))
        value = control.get("value")
        if signal not in {"risk.band", "risk.level", "core_risk.severity_level"}:
            continue
        if op == "==" and value is not None:
            bands.add(str(value).strip().lower())
        elif op == "in" and isinstance(value, list):
            for item in value:
                bands.add(str(item).strip().lower())
    return sorted(b for b in bands if b)


def _policy_matches_target(policy: Policy, target: Dict[str, Any]) -> bool:
    metadata = policy.metadata or {}
    target_env = str(target.get("env") or target.get("environment") or "").strip().lower()
    target_workflow = str(target.get("workflow_id") or target.get("workflow") or "").strip().lower()
    target_transition = str(target.get("transition_id") or target.get("transition") or "").strip().lower()
    target_risk = str(target.get("risk_band") or target.get("risk") or "").strip().lower()

    policy_env = str(metadata.get("env") or metadata.get("environment") or "").strip().lower()
    policy_workflow = str(metadata.get("workflow_id") or metadata.get("workflow") or "").strip().lower()
    policy_transition = str(metadata.get("transition_id") or metadata.get("transition") or "").strip().lower()

    if target_env and policy_env and target_env != policy_env:
        return False
    if target_workflow and policy_workflow and target_workflow != policy_workflow:
        return False
    if target_transition and policy_transition and target_transition != policy_transition:
        return False

    if target_risk:
        policy_risk_bands = _extract_risk_bands(policy)
        if policy_risk_bands and target_risk not in policy_risk_bands:
            return False

    return True


def lint_compiled_policies(
    policy_dir: str = "releasegate/policy/compiled",
    strict_schema: bool = True,
    *,
    base_dir: Optional[Union[str, Path]] = None,
    coverage_targets: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    issues: List[Dict[str, Any]] = []
    raw_docs = _iter_policy_yaml(policy_dir, base_dir=base_dir)
    by_policy_id: Dict[str, List[str]] = {}

    for source_file, doc in raw_docs:
        policy_id = doc.get("policy_id")
        if policy_id:
            by_policy_id.setdefault(str(policy_id), []).append(source_file)

    for policy_id, files in by_policy_id.items():
        if len(files) > 1:
            issues.append(
                _issue(
                    "ERROR",
                    "DUPLICATE_POLICY_ID",
                    f"Policy ID `{policy_id}` is declared in multiple files.",
                    policy_id=policy_id,
                    source_file=", ".join(files),
                )
            )

    loader = PolicyLoader(policy_dir=policy_dir, schema="compiled", strict=strict_schema, base_dir=base_dir)
    try:
        loaded = loader.load_all()
        policies = [policy for policy in loaded if isinstance(policy, Policy)]
    except Exception as exc:
        issues.append(
            _issue(
                "ERROR",
                "SCHEMA_VALIDATION_FAILED",
                f"Compiled policy schema validation failed: {exc}",
            )
        )
        return {
            "ok": False,
            "policy_dir": policy_dir,
            "policy_count": 0,
            "error_count": 1,
            "warning_count": 0,
            "issues": issues,
        }

    source_by_id: Dict[str, str] = {}
    for source_file, doc in raw_docs:
        policy_id = doc.get("policy_id")
        if policy_id:
            source_by_id[str(policy_id)] = source_file

    signature_map: Dict[str, List[Policy]] = {}
    has_risk_controls = False
    block_policy_count = 0
    for policy in policies:
        source_file = source_by_id.get(policy.policy_id)
        issues.extend(_check_internal_contradictions(policy, source_file))

        controls = _controls_for_policy(policy)
        for control in controls:
            signal = str(control.get("signal"))
            if signal.startswith("risk.") or signal.startswith("core_risk."):
                has_risk_controls = True

        if policy.enforcement.result == "BLOCK":
            block_policy_count += 1

        signature = json.dumps(sorted([_control_signature(control) for control in controls]), separators=(",", ":"))
        signature_map.setdefault(signature, []).append(policy)

    for overlapping in signature_map.values():
        if len(overlapping) <= 1:
            continue
        results = {policy.enforcement.result for policy in overlapping}
        if len(results) > 1:
            ids = ", ".join(sorted(policy.policy_id for policy in overlapping))
            issues.append(
                _issue(
                    "ERROR",
                    "AMBIGUOUS_OVERLAP",
                    f"Policies share identical triggers but different enforcement results: {ids}.",
                )
            )

    sorted_policies = sorted(policies, key=lambda policy: (_policy_priority(policy), policy.policy_id))
    for index, current in enumerate(sorted_policies):
        current_controls = _controls_for_policy(current)
        current_priority = _policy_priority(current)

        for prior in sorted_policies[:index]:
            prior_controls = _controls_for_policy(prior)
            prior_priority = _policy_priority(prior)
            if not _controls_overlap(prior_controls, current_controls):
                continue

            if (
                prior_priority == current_priority
                and prior.enforcement.result != current.enforcement.result
            ):
                issues.append(
                    _issue(
                        "ERROR",
                        "CONTRADICTORY_RULES",
                        f"Policies `{prior.policy_id}` and `{current.policy_id}` overlap with conflicting outcomes at priority {current_priority}.",
                        policy_id=current.policy_id,
                        source_file=source_by_id.get(current.policy_id),
                        metadata={
                            "conflicts_with": prior.policy_id,
                            "priority": current_priority,
                        },
                    )
                )

            if (
                prior_priority <= current_priority
                and prior.enforcement.result == current.enforcement.result
                and _is_broader_or_equal_controls(prior_controls, current_controls)
            ):
                issues.append(
                    _issue(
                        "WARNING",
                        "RULE_UNREACHABLE_SHADOWED",
                        f"Policy `{current.policy_id}` is shadowed by `{prior.policy_id}` and never changes evaluation outcome.",
                        policy_id=current.policy_id,
                        source_file=source_by_id.get(current.policy_id),
                        metadata={
                            "shadowed_by": prior.policy_id,
                            "priority": current_priority,
                        },
                    )
                )
                break

    if coverage_targets:
        for target in coverage_targets:
            if not isinstance(target, dict):
                continue
            if not any(_policy_matches_target(policy, target) for policy in policies):
                target_label = json.dumps(target, sort_keys=True, separators=(",", ":"))
                issues.append(
                    _issue(
                        "ERROR",
                        "COVERAGE_GAP",
                        f"No policy matches required coverage target {target_label}.",
                        metadata={"target": target},
                    )
                )

    if policies and not has_risk_controls:
        issues.append(
            _issue(
                "WARNING",
                "NO_RISK_CONTROL",
                "No compiled policy references `risk.*` or `core_risk.*` signals.",
            )
        )
    if policies and block_policy_count == 0:
        issues.append(
            _issue(
                "WARNING",
                "NO_BLOCK_POLICY",
                "No compiled policies produce `BLOCK`; enforcement may be advisory only.",
            )
        )

    error_count = sum(1 for issue in issues if issue["severity"] == "ERROR")
    warning_count = sum(1 for issue in issues if issue["severity"] == "WARNING")
    return {
        "ok": error_count == 0,
        "policy_dir": policy_dir,
        "policy_count": len(policies),
        "error_count": error_count,
        "warning_count": warning_count,
        "issues": issues,
    }


def _normalize_registry_transition_id(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


_RULE_SIMPLE_CONDITION_KEYS = {
    "risk",
    "environment",
    "changed_files_gt",
    "changed_files_gte",
    "changed_files_lt",
    "changed_files_lte",
}


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _validate_rule_condition_tree(node: Any, *, path: str) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    if not isinstance(node, dict):
        issues.append(
            _issue(
                "ERROR",
                "RULE_INVALID_LOGIC",
                f"`when` condition at `{path}` must be an object.",
                metadata={"path": path},
            )
        )
        return issues

    has_all = "all" in node
    has_any = "any" in node
    if has_all and has_any:
        issues.append(
            _issue(
                "ERROR",
                "RULE_INVALID_LOGIC",
                f"`when` condition at `{path}` cannot include both `all` and `any`.",
                metadata={"path": path},
            )
        )
        return issues

    unknown_keys = sorted(
        key for key in node.keys() if key not in _RULE_SIMPLE_CONDITION_KEYS and key not in {"all", "any"}
    )
    if unknown_keys:
        issues.append(
            _issue(
                "ERROR",
                "RULE_INVALID_LOGIC",
                f"`when` condition at `{path}` contains unsupported keys: {', '.join(unknown_keys)}.",
                metadata={"path": path, "keys": unknown_keys},
            )
        )

    if has_all or has_any:
        clause = "all" if has_all else "any"
        children = node.get(clause)
        if not isinstance(children, list) or not children:
            issues.append(
                _issue(
                    "ERROR",
                    "RULE_INVALID_LOGIC",
                    f"`{clause}` at `{path}` must contain at least one condition.",
                    metadata={"path": path, "clause": clause},
                )
            )
            return issues
        for index, child in enumerate(children):
            issues.extend(_validate_rule_condition_tree(child, path=f"{path}.{clause}[{index}]"))
        return issues

    simple_keys = sorted(key for key in node.keys() if key in _RULE_SIMPLE_CONDITION_KEYS)
    if not simple_keys:
        issues.append(
            _issue(
                "ERROR",
                "RULE_INVALID_LOGIC",
                f"`when` condition at `{path}` does not define any supported predicates.",
                metadata={"path": path},
            )
        )
        return issues

    gt = _as_int(node.get("changed_files_gt"))
    gte = _as_int(node.get("changed_files_gte"))
    lt = _as_int(node.get("changed_files_lt"))
    lte = _as_int(node.get("changed_files_lte"))
    lower_value: Optional[int] = None
    lower_inclusive = False
    if gt is not None:
        lower_value = gt
        lower_inclusive = False
    if gte is not None and (lower_value is None or gte > lower_value or (gte == lower_value and not lower_inclusive)):
        lower_value = gte
        lower_inclusive = True

    upper_value: Optional[int] = None
    upper_inclusive = False
    if lt is not None:
        upper_value = lt
        upper_inclusive = False
    if lte is not None and (upper_value is None or lte < upper_value or (lte == upper_value and not upper_inclusive)):
        upper_value = lte
        upper_inclusive = True

    if lower_value is not None and upper_value is not None:
        if lower_value > upper_value or (lower_value == upper_value and (not lower_inclusive or not upper_inclusive)):
            issues.append(
                _issue(
                    "ERROR",
                    "CONTRADICTORY_RULES",
                    f"`when` condition at `{path}` has contradictory changed_files bounds.",
                    metadata={"path": path},
                )
            )

    return issues

def _normalise_selector_value(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalise_conditions(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _selectors_overlap(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    for key in ("transition_id", "project_id", "workflow_id", "environment"):
        left_value = _normalise_selector_value(left.get(key))
        right_value = _normalise_selector_value(right.get(key))
        if left_value and right_value and left_value != right_value:
            return False
    left_conditions = _normalise_conditions(left.get("conditions"))
    right_conditions = _normalise_conditions(right.get("conditions"))
    if left_conditions and right_conditions:
        return json.dumps(left_conditions, sort_keys=True, separators=(",", ":")) == json.dumps(
            right_conditions, sort_keys=True, separators=(",", ":")
        )
    return True


def _selector_contains(broader: Dict[str, Any], narrower: Dict[str, Any]) -> bool:
    for key in ("transition_id", "project_id", "workflow_id", "environment"):
        broader_value = _normalise_selector_value(broader.get(key))
        narrower_value = _normalise_selector_value(narrower.get(key))
        if broader_value and broader_value != narrower_value:
            return False
    broader_conditions = _normalise_conditions(broader.get("conditions"))
    narrower_conditions = _normalise_conditions(narrower.get("conditions"))
    if not broader_conditions:
        return True
    return json.dumps(broader_conditions, sort_keys=True, separators=(",", ":")) == json.dumps(
        narrower_conditions, sort_keys=True, separators=(",", ":")
    )
def lint_registry_policy(policy_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Static checks for centralized policy-registry entries.
    The registry schema intentionally stays flexible, so these checks are heuristic
    and focus on hard governance hazards:
    - transition coverage gaps
    - impossible approval requirements
    - contradictory/overlapping transition rules
    """
    issues: List[Dict[str, Any]] = []
    payload = policy_json if isinstance(policy_json, dict) else {}

    transition_rules = payload.get("transition_rules")
    rules = transition_rules if isinstance(transition_rules, list) else []
    strict_fail_closed = bool(payload.get("strict_fail_closed", False))

    # Coverage checks
    required_transitions_raw = payload.get("required_transitions")
    required_transitions: List[str] = []
    if isinstance(required_transitions_raw, list):
        for item in required_transitions_raw:
            if isinstance(item, dict):
                transition_id = _normalize_registry_transition_id(
                    item.get("transition_id") or item.get("transition")
                )
            else:
                transition_id = _normalize_registry_transition_id(item)
            if transition_id:
                required_transitions.append(transition_id)

    covered_transitions: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        transition_id = _normalize_registry_transition_id(rule.get("transition_id"))
        if transition_id:
            covered_transitions.add(transition_id)

    for transition_id in sorted(set(required_transitions)):
        if transition_id in covered_transitions:
            continue
        issues.append(
            _issue(
                "ERROR" if strict_fail_closed else "WARNING",
                "TRANSITION_UNCOVERED",
                f"Required transition `{transition_id}` has no matching transition rule.",
            )
        )

    # Approval feasibility checks
    approval_cfg = payload.get("approval_requirements")
    if isinstance(approval_cfg, dict):
        try:
            min_approvals = int(approval_cfg.get("min_approvals", 0))
        except Exception:
            min_approvals = 0
        required_roles = approval_cfg.get("required_roles")
        required_roles = [str(role).strip() for role in required_roles] if isinstance(required_roles, list) else []
        role_capacity = approval_cfg.get("role_capacity")
        role_capacity = role_capacity if isinstance(role_capacity, dict) else {}

        if required_roles:
            missing_roles = [role for role in required_roles if int(role_capacity.get(role, 0) or 0) <= 0]
            if missing_roles:
                issues.append(
                    _issue(
                        "ERROR",
                        "APPROVAL_REQUIREMENT_IMPOSSIBLE",
                        f"Required approver roles are unavailable: {', '.join(sorted(missing_roles))}.",
                    )
                )

        if min_approvals > 0:
            if required_roles:
                available = sum(max(0, int(role_capacity.get(role, 0) or 0)) for role in required_roles)
            else:
                available = sum(max(0, int(value or 0)) for value in role_capacity.values())
            if available < min_approvals:
                issues.append(
                    _issue(
                        "ERROR",
                        "APPROVAL_REQUIREMENT_IMPOSSIBLE",
                        f"min_approvals={min_approvals} exceeds available approvers ({available}).",
                )
            )

    # Rule-logic checks for advanced nested all/any conditions.
    registry_rules_raw = payload.get("rules")
    registry_rules = registry_rules_raw if isinstance(registry_rules_raw, list) else []
    seen_rule_ids: Dict[str, int] = {}
    for index, rule in enumerate(registry_rules):
        if not isinstance(rule, dict):
            continue
        rule_id = str(rule.get("rule_id") or rule.get("id") or f"rule-{index + 1}").strip()
        prior_idx = seen_rule_ids.get(rule_id)
        if prior_idx is not None:
            issues.append(
                _issue(
                    "ERROR",
                    "OVERLAPPING_RULES",
                    f"Duplicate rule identifier `{rule_id}` at indexes {prior_idx} and {index}.",
                    metadata={"rule_id": rule_id, "indexes": [prior_idx, index]},
                )
            )
        else:
            seen_rule_ids[rule_id] = index

        when = rule.get("when")
        if when is not None:
            issues.extend(_validate_rule_condition_tree(when, path=f"rules[{index}].when"))

        require = rule.get("require") if isinstance(rule.get("require"), dict) else {}
        required_roles = require.get("roles")
        top_level_roles = rule.get("required_roles")
        if isinstance(required_roles, list) and isinstance(top_level_roles, list):
            roles_a = sorted({str(role).strip().lower() for role in required_roles if str(role).strip()})
            roles_b = sorted({str(role).strip().lower() for role in top_level_roles if str(role).strip()})
            if roles_a and roles_b and roles_a != roles_b:
                issues.append(
                    _issue(
                        "ERROR",
                        "CONTRADICTORY_RULES",
                        (
                            f"Rule `{rule_id}` defines conflicting required roles in `require.roles` "
                            "and `required_roles`."
                        ),
                        metadata={"rule_id": rule_id},
                    )
                )
        require_approvals = require.get("approvals")
        top_level_approvals = rule.get("required_approvals")
        if require_approvals is not None and top_level_approvals is not None:
            approvals_a = _as_int(require_approvals)
            approvals_b = _as_int(top_level_approvals)
            if approvals_a is not None and approvals_b is not None and approvals_a != approvals_b:
                issues.append(
                    _issue(
                        "ERROR",
                        "CONTRADICTORY_RULES",
                        (
                            f"Rule `{rule_id}` defines conflicting required approvals in `require.approvals` "
                            "and `required_approvals`."
                        ),
                        metadata={"rule_id": rule_id},
                    )
                )

    # Overlap + contradiction checks
    signatures: Dict[str, Dict[str, Any]] = {}
    structural_rules: List[Dict[str, Any]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        transition_id = _normalize_registry_transition_id(rule.get("transition_id"))
        if not transition_id:
            continue
        result = str(rule.get("result") or rule.get("enforcement") or "ALLOW").strip().upper()
        selector = {
            "transition_id": transition_id,
            "project_id": str(rule.get("project_id") or "").strip().lower(),
            "workflow_id": str(rule.get("workflow_id") or "").strip().lower(),
            "environment": str(rule.get("environment") or "").strip().lower(),
            "conditions": rule.get("conditions") if isinstance(rule.get("conditions"), dict) else {},
        }
        signature = json.dumps(selector, sort_keys=True, separators=(",", ":"))
        try:
            priority = int(rule.get("priority") or 1000)
        except Exception:
            priority = 1000

        structural_rules.append(
            {
                "index": index,
                "priority": priority,
                "result": result,
                "selector": selector,
                "transition_id": transition_id,
            }
        )

        prior = signatures.get(signature)
        if prior is None:
            signatures[signature] = {
                "result": result,
                "index": index,
                "transition_id": transition_id,
            }
            continue
        if prior["result"] != result:
            issues.append(
                _issue(
                    "ERROR",
                    "OVERLAPPING_RULES",
                    (
                        f"Transition rule overlap detected for `{transition_id}` "
                        f"with conflicting outcomes `{prior['result']}` and `{result}`."
                    ),
                )
            )
            issues.append(
                _issue(
                    "ERROR",
                    "CONTRADICTORY_RULES",
                    (
                        f"Conflicting transition outcomes for `{transition_id}` at rule indexes "
                        f"{prior['index']} and {index}."
                    ),
                )
            )

    structural_rules.sort(key=lambda item: (item["priority"], item["index"]))
    for idx, current in enumerate(structural_rules):
        for prior in structural_rules[:idx]:
            if not _selectors_overlap(prior["selector"], current["selector"]):
                continue

            if prior["priority"] == current["priority"] and prior["result"] != current["result"]:
                issues.append(
                    _issue(
                        "ERROR",
                        "AMBIGUOUS_OVERLAP",
                        (
                            f"Transition rules at indexes {prior['index']} and {current['index']} "
                            "overlap at the same priority with conflicting outcomes."
                        ),
                        metadata={
                            "rule_indexes": [prior["index"], current["index"]],
                            "priority": current["priority"],
                        },
                    )
                )

            if _selector_contains(prior["selector"], current["selector"]):
                if prior["result"] != current["result"]:
                    issues.append(
                        _issue(
                            "ERROR",
                            "CONTRADICTORY_RULES",
                            (
                                f"Higher precedence rule at index {prior['index']} conflicts with narrower "
                                f"rule at index {current['index']}."
                            ),
                            metadata={
                                "rule_indexes": [prior["index"], current["index"]],
                                "priority": [prior["priority"], current["priority"]],
                            },
                        )
                    )
                else:
                    issues.append(
                        _issue(
                            "WARNING",
                            "RULE_UNREACHABLE_SHADOWED",
                            (
                                f"Rule at index {current['index']} is shadowed by higher precedence "
                                f"rule at index {prior['index']}."
                            ),
                            metadata={
                                "rule_index": current["index"],
                                "shadowed_by": prior["index"],
                            },
                        )
                    )
                break

    error_count = sum(1 for issue in issues if issue.get("severity") == "ERROR")
    warning_count = sum(1 for issue in issues if issue.get("severity") == "WARNING")
    return {
        "ok": error_count == 0,
        "error_count": error_count,
        "warning_count": warning_count,
        "issues": issues,
    }


def format_lint_report(report: Dict[str, Any]) -> str:
    status = "PASS" if report.get("ok") else "FAIL"
    lines = [
        f"Policy Lint: {status}",
        f"Policy Dir: {report.get('policy_dir')}",
        f"Policies: {report.get('policy_count', 0)}",
        f"Errors: {report.get('error_count', 0)}",
        f"Warnings: {report.get('warning_count', 0)}",
    ]
    issues = report.get("issues") or []
    if issues:
        lines.append("")
        lines.append("Issues:")
        for issue in issues:
            location = ""
            if issue.get("policy_id"):
                location += f" policy={issue['policy_id']}"
            if issue.get("source_file"):
                location += f" file={issue['source_file']}"
            lines.append(
                f"- [{issue.get('severity')}] {issue.get('code')}: {issue.get('message')}{location}"
            )
    return "\n".join(lines)
