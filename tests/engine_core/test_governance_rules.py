from __future__ import annotations

from releasegate.engine_core.evaluate import evaluate
from releasegate.engine_core.types import (
    ApprovalRecord,
    ConditionRule,
    EvaluationInput,
    NormalizedContext,
)


def _ctx(**overrides) -> NormalizedContext:
    payload = {
        "evaluation_kind": "jira_transition",
        "environment": "production",
        "issue_key": "RG-100",
        "transition_id": "2",
        "repo": "acme/service",
        "pr_number": 42,
        "actor_id": "actor-1",
        "evaluation_time": "2026-02-26T00:00:00+00:00",
        "risk_level": "LOW",
        "changed_files": 5,
    }
    payload.update(overrides)
    return NormalizedContext(**payload)


def test_engine_core_blocks_when_pr_author_approves_override():
    decision = evaluate(
        EvaluationInput(
            context=_ctx(
                pr_author_id="alice@example.com",
                override_approvers=("alice@example.com",),
            ),
            enforce_sod=True,
        )
    )
    assert decision.allow is False
    assert decision.status == "BLOCKED"
    assert decision.reason_code == "SOD_PR_AUTHOR_APPROVED_OVERRIDE"


def test_engine_core_blocks_when_requester_self_approves_override():
    decision = evaluate(
        EvaluationInput(
            context=_ctx(
                override_requester_id="requester-1",
                override_approvers=("requester-1",),
            ),
            enforce_sod=True,
        )
    )
    assert decision.allow is False
    assert decision.status == "BLOCKED"
    assert decision.reason_code == "SOD_SELF_APPROVAL"


def test_engine_core_blocks_duplicate_approver_roles():
    decision = evaluate(
        EvaluationInput(
            context=_ctx(
                approvals=(
                    ApprovalRecord(actor_id="sec-1", role="Security"),
                    ApprovalRecord(actor_id="sec-1", role="EngineeringManager"),
                ),
            ),
            enforce_sod=True,
        )
    )
    assert decision.allow is False
    assert decision.status == "BLOCKED"
    assert decision.reason_code == "SOD_DUPLICATE_APPROVAL"


def test_engine_core_ignores_replayed_duplicate_approval_event():
    decision = evaluate(
        EvaluationInput(
            context=_ctx(
                approvals=(
                    ApprovalRecord(actor_id="sec-1", role="Security"),
                    ApprovalRecord(actor_id="sec-1", role="Security"),
                ),
            ),
            enforce_sod=True,
        )
    )
    assert decision.allow is True
    assert decision.status == "ALLOWED"
    assert decision.reason_code == "POLICY_ALLOWED"


def test_engine_core_condition_rule_requires_approvals_and_roles():
    decision = evaluate(
        EvaluationInput(
            context=_ctx(
                risk_level="HIGH",
                changed_files=40,
                approvals=(ApprovalRecord(actor_id="em-1", role="EM"),),
            ),
            condition_rules=(
                ConditionRule(
                    rule_id="prod-high-risk",
                    when={
                        "all": [
                            {"risk": "HIGH"},
                            {"changed_files_gt": 25},
                            {"environment": "production"},
                        ]
                    },
                    result="ALLOW",
                    required_approvals=2,
                    required_roles=("EM", "Security"),
                ),
            ),
        )
    )
    assert decision.allow is True
    assert decision.status == "CONDITIONAL"
    assert decision.reason_code == "POLICY_RULE_REQUIREMENTS_UNMET"
    assert any("requires 2 distinct approvals" in requirement for requirement in decision.requirements)


def test_engine_core_sod_runs_before_approval_requirements():
    decision = evaluate(
        EvaluationInput(
            context=_ctx(
                risk_level="HIGH",
                changed_files=40,
                pr_author_id="alice@example.com",
                override_approvers=("alice@example.com",),
                approvals=(
                    ApprovalRecord(actor_id="em-1", role="EM"),
                    ApprovalRecord(actor_id="sec-1", role="Security"),
                ),
            ),
            condition_rules=(
                ConditionRule(
                    rule_id="prod-high-risk",
                    when={"all": [{"risk": "HIGH"}, {"environment": "production"}]},
                    result="ALLOW",
                    required_approvals=2,
                    required_roles=("EM", "Security"),
                ),
            ),
            enforce_sod=True,
        )
    )
    assert decision.allow is False
    assert decision.status == "BLOCKED"
    assert decision.reason_code == "SOD_PR_AUTHOR_APPROVED_OVERRIDE"


def test_engine_core_condition_rule_supports_nested_any_all_block():
    decision = evaluate(
        EvaluationInput(
            context=_ctx(risk_level="HIGH", changed_files=5, environment="production"),
            condition_rules=(
                ConditionRule(
                    rule_id="block-high-risk-prod",
                    when={
                        "all": [
                            {"risk": "HIGH"},
                            {
                                "any": [
                                    {"environment": "production"},
                                    {"changed_files_gt": 25},
                                ]
                            },
                        ]
                    },
                    result="BLOCK",
                ),
            ),
        )
    )
    assert decision.allow is False
    assert decision.status == "BLOCKED"
    assert decision.reason_code == "POLICY_RULE_BLOCKED"


def test_engine_core_condition_rules_are_evaluated_by_priority():
    decision = evaluate(
        EvaluationInput(
            context=_ctx(risk_level="HIGH", changed_files=30, environment="production"),
            condition_rules=(
                ConditionRule(
                    rule_id="late-rule",
                    when={"all": [{"risk": "HIGH"}]},
                    result="WARN",
                    priority=500,
                ),
                ConditionRule(
                    rule_id="early-rule",
                    when={"all": [{"risk": "HIGH"}]},
                    result="WARN",
                    priority=10,
                ),
            ),
        )
    )
    assert decision.status == "CONDITIONAL"
    assert decision.reasons[0].details.get("rule_id") == "early-rule"
