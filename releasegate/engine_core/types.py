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
class ApprovalRecord:
    actor_id: str
    role: str = ""


@dataclass(frozen=True)
class ConditionRule:
    rule_id: str
    when: Mapping[str, Any] = field(default_factory=dict)
    result: str = "ALLOW"
    priority: int = 1000
    required_approvals: int = 0
    required_roles: Tuple[str, ...] = ()


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
    risk_level: str = ""
    changed_files: Optional[int] = None
    pr_author_id: str = ""
    override_requester_id: str = ""
    override_approvers: Tuple[str, ...] = ()
    approvals: Tuple[ApprovalRecord, ...] = ()
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
    condition_rules: Tuple[ConditionRule, ...] = ()
    enforce_sod: bool = False
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


def approval_record_to_dict(value: ApprovalRecord) -> Dict[str, Any]:
    return {
        "actor_id": value.actor_id,
        "role": value.role,
    }


def condition_rule_to_dict(value: ConditionRule) -> Dict[str, Any]:
    return {
        "rule_id": value.rule_id,
        "when": dict(value.when or {}),
        "result": value.result,
        "priority": value.priority,
        "required_approvals": value.required_approvals,
        "required_roles": list(value.required_roles),
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
        "risk_level": value.risk_level,
        "changed_files": value.changed_files,
        "pr_author_id": value.pr_author_id,
        "override_requester_id": value.override_requester_id,
        "override_approvers": list(value.override_approvers),
        "approvals": [approval_record_to_dict(item) for item in value.approvals],
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
        "condition_rules": [condition_rule_to_dict(item) for item in value.condition_rules],
        "enforce_sod": value.enforce_sod,
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
