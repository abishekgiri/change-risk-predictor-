from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

from releasegate.engine_core.types import (
    Decision,
    DecisionReason,
    EvaluationInput,
    NormalizedContext,
    PolicyOutcome,
    PolicyRef,
    decision_to_dict,
)
from releasegate.utils.canonical import canonical_json


_ALLOW_STATUSES = {"ALLOWED", "SKIPPED", "CONDITIONAL"}


def _sorted_policy_refs(policy_refs: Sequence[PolicyRef]) -> Tuple[PolicyRef, ...]:
    return tuple(
        sorted(
            policy_refs,
            key=lambda item: (
                str(item.policy_id or ""),
                str(item.policy_version or ""),
                str(item.policy_hash or ""),
                str(item.source or ""),
            ),
        )
    )


def _sorted_policy_outcomes(policy_outcomes: Sequence[PolicyOutcome]) -> Tuple[PolicyOutcome, ...]:
    return tuple(
        sorted(
            policy_outcomes,
            key=lambda item: (
                str(item.policy_id or ""),
                str(item.status or ""),
                tuple(str(v) for v in item.violations),
            ),
        )
    )


def _sorted_condition_rules(input_data: EvaluationInput):
    return tuple(
        sorted(
            input_data.condition_rules,
            key=lambda rule: (
                int(rule.priority or 0),
                str(rule.rule_id or ""),
                canonical_json(dict(rule.when or {})),
            ),
        )
    )


def _reason_code_for_status(status: str, success_reason_code: str) -> str:
    if status == "BLOCKED":
        return "POLICY_BLOCKED"
    if status == "CONDITIONAL":
        return "POLICY_CONDITIONAL"
    return success_reason_code or "POLICY_ALLOWED"


def _normalized_principal(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text


def _sod_reasons(context: NormalizedContext) -> Tuple[DecisionReason, ...]:
    reasons: List[DecisionReason] = []
    pr_author = _normalized_principal(context.pr_author_id)
    requester = _normalized_principal(context.override_requester_id)
    override_approvers = {_normalized_principal(v) for v in context.override_approvers if _normalized_principal(v)}
    if pr_author and pr_author in override_approvers:
        reasons.append(
            DecisionReason(
                code="SOD_PR_AUTHOR_APPROVED_OVERRIDE",
                message="PR author cannot approve override.",
                details={"pr_author_id": pr_author},
            )
        )
    if requester and requester in override_approvers:
        reasons.append(
            DecisionReason(
                code="SOD_SELF_APPROVAL",
                message="Override requester cannot self-approve.",
                details={"override_requester_id": requester},
            )
        )

    approvals_by_actor: Dict[str, set[str]] = {}
    approval_actors: set[str] = set()
    for approval in context.approvals:
        actor = _normalized_principal(approval.actor_id)
        if not actor:
            continue
        approval_actors.add(actor)
        role = str(approval.role or "").strip().lower()
        if role:
            approvals_by_actor.setdefault(actor, set()).add(role)
        else:
            approvals_by_actor.setdefault(actor, set())
    for actor_id, roles in approvals_by_actor.items():
        if len(roles) <= 1:
            continue
        unique_roles = sorted(roles)
        reasons.append(
            DecisionReason(
                code="SOD_DUPLICATE_APPROVAL",
                message="Same actor cannot approve multiple times.",
                details={"actor_id": actor_id, "roles": unique_roles},
            )
        )

    duplicate_actors = sorted(approval_actors.intersection(override_approvers))
    if duplicate_actors:
        reasons.append(
            DecisionReason(
                code="SOD_APPROVER_REUSED",
                message="Override approver cannot also satisfy policy approvals.",
                details={"actors": duplicate_actors},
            )
        )
    return tuple(reasons)


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _simple_condition_match(node: Dict[str, Any], context: NormalizedContext) -> bool:
    risk_expected = str(node.get("risk") or "").strip()
    if risk_expected and str(context.risk_level or "").strip().upper() != risk_expected.upper():
        return False
    if node.get("changed_files_gt") is not None:
        if context.changed_files is None or int(context.changed_files) <= _to_int(node.get("changed_files_gt")):
            return False
    if node.get("changed_files_gte") is not None:
        if context.changed_files is None or int(context.changed_files) < _to_int(node.get("changed_files_gte")):
            return False
    if node.get("changed_files_lt") is not None:
        if context.changed_files is None or int(context.changed_files) >= _to_int(node.get("changed_files_lt")):
            return False
    if node.get("changed_files_lte") is not None:
        if context.changed_files is None or int(context.changed_files) > _to_int(node.get("changed_files_lte")):
            return False
    env_expected = str(node.get("environment") or "").strip()
    if env_expected and str(context.environment or "").strip().lower() != env_expected.lower():
        return False
    return True


def _match_condition_tree(node: Any, context: NormalizedContext) -> bool:
    if not isinstance(node, dict):
        return False
    if "all" in node:
        children = node.get("all")
        if not isinstance(children, list) or not children:
            return False
        return all(_match_condition_tree(child, context) for child in children)
    if "any" in node:
        children = node.get("any")
        if not isinstance(children, list) or not children:
            return False
        return any(_match_condition_tree(child, context) for child in children)
    return _simple_condition_match(node, context)


def _apply_condition_rules(
    *,
    input_data: EvaluationInput,
    status: str,
    reasons: List[DecisionReason],
    requirements: List[str],
    blocking_policy_ids: List[str],
) -> Tuple[str, List[DecisionReason], List[str], List[str]]:
    if not input_data.condition_rules:
        return status, reasons, requirements, blocking_policy_ids

    approver_ids = {
        _normalized_principal(approval.actor_id)
        for approval in input_data.context.approvals
        if _normalized_principal(approval.actor_id)
    }
    approver_roles = {str(approval.role or "").strip().lower() for approval in input_data.context.approvals if str(approval.role or "").strip()}

    for rule in _sorted_condition_rules(input_data):
        if not _match_condition_tree(dict(rule.when or {}), input_data.context):
            continue

        required_approvals = max(0, int(rule.required_approvals or 0))
        required_roles = [str(role).strip() for role in rule.required_roles if str(role).strip()]
        unmet_requirements: List[str] = []
        if required_approvals > 0 and len(approver_ids) < required_approvals:
            unmet_requirements.append(
                f"Rule `{rule.rule_id}` requires {required_approvals} distinct approvals (found {len(approver_ids)})."
            )
        if required_roles:
            missing = [role for role in required_roles if role.lower() not in approver_roles]
            if missing:
                unmet_requirements.append(
                    f"Rule `{rule.rule_id}` is missing approval roles: {', '.join(sorted(missing))}."
                )

        effect = str(rule.result or "ALLOW").strip().upper()
        if effect in {"BLOCK", "BLOCKED", "DENY", "DENIED"}:
            status = "BLOCKED"
            blocking_policy_ids.append(rule.rule_id)
            reasons.append(
                DecisionReason(
                    code="POLICY_RULE_BLOCKED",
                    message=f"Rule `{rule.rule_id}` blocked evaluation.",
                    details={"rule_id": rule.rule_id, "effect": effect},
                )
            )
        elif effect in {"WARN", "CONDITIONAL"} and status != "BLOCKED":
            status = "CONDITIONAL"
            reasons.append(
                DecisionReason(
                    code="POLICY_RULE_CONDITIONAL",
                    message=f"Rule `{rule.rule_id}` requires conditional approvals.",
                    details={"rule_id": rule.rule_id, "effect": effect},
                )
            )

        if unmet_requirements and status != "BLOCKED":
            status = "CONDITIONAL"
            requirements.extend(unmet_requirements)
            reasons.append(
                DecisionReason(
                    code="POLICY_RULE_REQUIREMENTS_UNMET",
                    message=f"Rule `{rule.rule_id}` has unmet approval requirements.",
                    details={
                        "rule_id": rule.rule_id,
                        "required_approvals": required_approvals,
                        "required_roles": required_roles,
                    },
                )
            )

    return status, reasons, requirements, blocking_policy_ids


def _policy_decision(input_data: EvaluationInput) -> Decision:
    status = input_data.success_status or "ALLOWED"
    blocking_policy_ids: List[str] = []
    requirements: List[str] = []
    reasons: List[DecisionReason] = []

    for outcome in _sorted_policy_outcomes(input_data.policy_outcomes):
        raw_status = str(outcome.status or "").strip().upper()
        if raw_status == "BLOCK":
            status = "BLOCKED"
            blocking_policy_ids.append(str(outcome.policy_id))
            requirement_values = list(outcome.violations) or [f"Policy `{outcome.policy_id}` blocked evaluation."]
            requirements.extend(requirement_values)
            reasons.append(
                DecisionReason(
                    code="POLICY_BLOCKED",
                    message=f"Policy `{outcome.policy_id}` blocked evaluation.",
                    details={
                        "policy_id": outcome.policy_id,
                        "violations": list(outcome.violations),
                    },
                )
            )
            continue

        if raw_status == "WARN" and status != "BLOCKED":
            status = "CONDITIONAL"
            requirement_values = list(outcome.violations) or [f"Policy `{outcome.policy_id}` requires additional approvals."]
            requirements.extend(requirement_values)
            reasons.append(
                DecisionReason(
                    code="POLICY_CONDITIONAL",
                    message=f"Policy `{outcome.policy_id}` requires conditional approvals.",
                    details={
                        "policy_id": outcome.policy_id,
                        "violations": list(outcome.violations),
                    },
                )
            )

    status, reasons, requirements, blocking_policy_ids = _apply_condition_rules(
        input_data=input_data,
        status=status,
        reasons=reasons,
        requirements=requirements,
        blocking_policy_ids=blocking_policy_ids,
    )

    reason_code = _reason_code_for_status(status, input_data.success_reason_code)
    if reasons:
        reason_code = str(reasons[0].code or reason_code)
    if not reasons:
        reasons.append(
            DecisionReason(
                code=reason_code,
                message="Policy evaluation completed.",
                details={},
            )
        )

    return Decision(
        allow=status in _ALLOW_STATUSES,
        status=status,
        reason_code=reason_code,
        reasons=tuple(reasons),
        policy_refs=_sorted_policy_refs(input_data.policy_refs),
        blocking_policy_ids=tuple(blocking_policy_ids),
        requirements=tuple(requirements),
    )


def evaluate(input_data: EvaluationInput) -> Decision:
    """
    Pure deterministic evaluator.
    - No DB/network/env/clock reads.
    - Same `EvaluationInput` content produces same `Decision`.
    """
    if input_data.enforce_sod:
        sod_reasons = _sod_reasons(input_data.context)
        if sod_reasons:
            return Decision(
                allow=False,
                status="BLOCKED",
                reason_code=str(sod_reasons[0].code or "SOD_CONFLICT"),
                reasons=sod_reasons,
                policy_refs=_sorted_policy_refs(input_data.policy_refs),
                blocking_policy_ids=(),
                requirements=(),
            )

    if input_data.check_reasons:
        reason = input_data.check_reasons[0]
        return Decision(
            allow=False,
            status="BLOCKED",
            reason_code=str(reason.code or "BLOCKED"),
            reasons=tuple(input_data.check_reasons),
            policy_refs=_sorted_policy_refs(input_data.policy_refs),
            blocking_policy_ids=(),
            requirements=(),
        )
    return _policy_decision(input_data)


def decision_to_canonical_json(decision: Decision) -> str:
    return canonical_json(decision_to_dict(decision))


def evaluate_to_canonical_json(input_data: EvaluationInput) -> str:
    return decision_to_canonical_json(evaluate(input_data))


def reasons_from_checks(checks: Iterable[Tuple[bool, str, str, Dict[str, Any]]]) -> Tuple[DecisionReason, ...]:
    reasons: List[DecisionReason] = []
    for failed, code, message, details in checks:
        if not bool(failed):
            continue
        reasons.append(
            DecisionReason(
                code=str(code),
                message=str(message),
                details=dict(details or {}),
            )
        )
    return tuple(reasons)
