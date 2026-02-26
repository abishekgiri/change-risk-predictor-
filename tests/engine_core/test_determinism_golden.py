from __future__ import annotations

from releasegate.engine_core.evaluate import decision_to_canonical_json, evaluate
from releasegate.engine_core.types import (
    DecisionReason,
    EvaluationInput,
    NormalizedContext,
    PolicyOutcome,
    PolicyRef,
)


def _base_context(**overrides):
    payload = {
        "evaluation_kind": "jira_transition",
        "environment": "PRODUCTION",
        "issue_key": "RG-ENGINE-1",
        "transition_id": "2",
        "repo": "abishekgiri/change-risk-predictor-",
        "pr_number": 28,
        "actor_id": "acct-1",
        "evaluation_time": "2026-02-26T00:00:00+00:00",
        "metadata": {},
    }
    payload.update(overrides)
    return NormalizedContext(**payload)


def test_engine_core_simple_allow_is_deterministic():
    inp = EvaluationInput(
        context=_base_context(),
        policy_refs=(PolicyRef(policy_id="ORG-BASE", policy_version="4", policy_hash="h-org"),),
        policy_outcomes=(PolicyOutcome.from_untyped(policy_id="ORG-BASE", status="COMPLIANT"),),
    )
    first = decision_to_canonical_json(evaluate(inp))
    second = decision_to_canonical_json(evaluate(inp))
    assert first == second
    assert '"status":"ALLOWED"' in first
    assert '"reason_code":"POLICY_ALLOWED"' in first


def test_engine_core_deny_with_reasons_is_deterministic():
    inp = EvaluationInput(
        context=_base_context(issue_key="RG-ENGINE-2"),
        policy_refs=(
            PolicyRef(policy_id="ORG-BASE", policy_version="4", policy_hash="h-org"),
            PolicyRef(policy_id="PR-STRICT", policy_version="2", policy_hash="h-pr"),
        ),
        policy_outcomes=(
            PolicyOutcome.from_untyped(
                policy_id="PR-STRICT",
                status="BLOCK",
                violations=["risk.score 92 > 80", "security approval missing"],
            ),
            PolicyOutcome.from_untyped(policy_id="ORG-BASE", status="COMPLIANT"),
        ),
    )
    first = decision_to_canonical_json(evaluate(inp))
    second = decision_to_canonical_json(evaluate(inp))
    assert first == second
    assert '"status":"BLOCKED"' in first
    assert '"reason_code":"POLICY_BLOCKED"' in first
    assert '"blocking_policy_ids":["PR-STRICT"]' in first


def test_engine_core_policy_inheritance_edge_blocks_deterministically():
    inp = EvaluationInput(
        context=_base_context(issue_key="RG-ENGINE-3"),
        policy_refs=(
            PolicyRef(policy_id="TRANSITION-2", policy_version="1", policy_hash="h-t"),
            PolicyRef(policy_id="WORKFLOW-REL", policy_version="7", policy_hash="h-w"),
            PolicyRef(policy_id="PROJECT-RG", policy_version="3", policy_hash="h-p"),
            PolicyRef(policy_id="ORG-BASE", policy_version="9", policy_hash="h-o"),
        ),
        policy_outcomes=(
            PolicyOutcome.from_untyped(policy_id="PROJECT-RG", status="WARN", violations=["manual approval required"]),
            PolicyOutcome.from_untyped(policy_id="TRANSITION-2", status="BLOCK", violations=["override expired"]),
            PolicyOutcome.from_untyped(policy_id="WORKFLOW-REL", status="COMPLIANT"),
            PolicyOutcome.from_untyped(policy_id="ORG-BASE", status="COMPLIANT"),
        ),
    )
    first = decision_to_canonical_json(evaluate(inp))
    second = decision_to_canonical_json(evaluate(inp))
    assert first == second
    assert '"status":"BLOCKED"' in first
    assert '"blocking_policy_ids":["TRANSITION-2"]' in first
    # Policy refs are sorted deterministically in output.
    assert first.index('"policy_id":"ORG-BASE"') < first.index('"policy_id":"PROJECT-RG"')


def test_engine_core_context_ordering_does_not_change_output():
    inp_a = EvaluationInput(
        context=_base_context(metadata={"project": "RG", "workflow": "release", "env": "prod"}),
        check_reasons=(
            DecisionReason(
                code="SIGNAL_STALE",
                message="risk signal stale",
                details={"age_seconds": 900, "max_age_seconds": 300},
            ),
        ),
    )
    inp_b = EvaluationInput(
        context=_base_context(metadata={"env": "prod", "workflow": "release", "project": "RG"}),
        check_reasons=(
            DecisionReason(
                code="SIGNAL_STALE",
                message="risk signal stale",
                details={"max_age_seconds": 300, "age_seconds": 900},
            ),
        ),
    )
    out_a = decision_to_canonical_json(evaluate(inp_a))
    out_b = decision_to_canonical_json(evaluate(inp_b))
    assert out_a == out_b
