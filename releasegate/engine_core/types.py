from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True)
class PolicyRef:
    policy_id: str
    policy_version: str = ""
    policy_hash: str = ""
    source: str = ""


@dataclass(frozen=True)
class DecisionReason:
    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedContext:
    evaluation_kind: str
    environment: str
    issue_key: str = ""
    transition_id: str = ""
    repo: str = ""
    pr_number: Optional[int] = None
    actor_id: str = ""
    evaluation_time: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyOutcome:
    policy_id: str
    status: str
    violations: Tuple[str, ...] = ()

    @classmethod
    def from_untyped(
        cls,
        *,
        policy_id: str,
        status: str,
        violations: Optional[Sequence[str]] = None,
    ) -> "PolicyOutcome":
        items = tuple(str(v) for v in (violations or []) if str(v).strip())
        return cls(policy_id=str(policy_id), status=str(status), violations=items)


@dataclass(frozen=True)
class EvaluationInput:
    context: NormalizedContext
    policy_refs: Tuple[PolicyRef, ...] = ()
    policy_outcomes: Tuple[PolicyOutcome, ...] = ()
    check_reasons: Tuple[DecisionReason, ...] = ()
    success_status: str = "ALLOWED"
    success_reason_code: str = "POLICY_ALLOWED"


@dataclass(frozen=True)
class Decision:
    allow: bool
    status: str
    reason_code: str
    reasons: Tuple[DecisionReason, ...]
    policy_refs: Tuple[PolicyRef, ...]
    blocking_policy_ids: Tuple[str, ...]
    requirements: Tuple[str, ...]


def policy_ref_to_dict(value: PolicyRef) -> Dict[str, Any]:
    return {
        "policy_id": value.policy_id,
        "policy_version": value.policy_version,
        "policy_hash": value.policy_hash,
        "source": value.source,
    }


def decision_reason_to_dict(value: DecisionReason) -> Dict[str, Any]:
    return {
        "code": value.code,
        "message": value.message,
        "details": dict(value.details or {}),
    }


def normalized_context_to_dict(value: NormalizedContext) -> Dict[str, Any]:
    return {
        "evaluation_kind": value.evaluation_kind,
        "environment": value.environment,
        "issue_key": value.issue_key,
        "transition_id": value.transition_id,
        "repo": value.repo,
        "pr_number": value.pr_number,
        "actor_id": value.actor_id,
        "evaluation_time": value.evaluation_time,
        "metadata": dict(value.metadata or {}),
    }


def policy_outcome_to_dict(value: PolicyOutcome) -> Dict[str, Any]:
    return {
        "policy_id": value.policy_id,
        "status": value.status,
        "violations": list(value.violations),
    }


def evaluation_input_to_dict(value: EvaluationInput) -> Dict[str, Any]:
    return {
        "context": normalized_context_to_dict(value.context),
        "policy_refs": [policy_ref_to_dict(item) for item in value.policy_refs],
        "policy_outcomes": [policy_outcome_to_dict(item) for item in value.policy_outcomes],
        "check_reasons": [decision_reason_to_dict(item) for item in value.check_reasons],
        "success_status": value.success_status,
        "success_reason_code": value.success_reason_code,
    }


def decision_to_dict(value: Decision) -> Dict[str, Any]:
    return {
        "allow": value.allow,
        "status": value.status,
        "reason_code": value.reason_code,
        "reasons": [decision_reason_to_dict(item) for item in value.reasons],
        "policy_refs": [policy_ref_to_dict(item) for item in value.policy_refs],
        "blocking_policy_ids": list(value.blocking_policy_ids),
        "requirements": list(value.requirements),
    }
