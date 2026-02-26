from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

from releasegate.engine_core.types import (
    Decision,
    DecisionReason,
    EvaluationInput,
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


def _reason_code_for_status(status: str, success_reason_code: str) -> str:
    if status == "BLOCKED":
        return "POLICY_BLOCKED"
    if status == "CONDITIONAL":
        return "POLICY_CONDITIONAL"
    return success_reason_code or "POLICY_ALLOWED"


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

    reason_code = _reason_code_for_status(status, input_data.success_reason_code)
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
