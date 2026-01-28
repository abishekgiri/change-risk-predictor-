import pytest
from releasegate.decision.factory import DecisionFactory
from releasegate.policy.evaluator import PolicyResult
from releasegate.policy.types import PolicyDef, PolicyAction, Requirement, PolicyConditions
from releasegate.context.types import EvaluationContext
from releasegate.context.builder import ContextBuilder

# Mock objects
@pytest.fixture
def mock_ctx():
    return ContextBuilder().with_actor("u","l").with_change("r","1",[],change_type="PR").build()

def test_decision_factory_targets(mock_ctx):
    """Test that factory populates enforcement targets."""
    result = PolicyResult(
        decision="ALLOWED",
        matched_policies=[],
        blocking_policies=[],
        requirements=None,
        message="OK"
    )
    
    decision = DecisionFactory.create(mock_ctx, result, [])
    
    assert decision.enforcement_targets.repository == "r"
    assert decision.enforcement_targets.pr_number == 1
    # Check defaults
    assert decision.enforcement_targets.github_check_name == "ReleaseGate"

def test_decision_factory_blocked(mock_ctx):
    result = PolicyResult(
        decision="BLOCKED",
        matched_policies=["p1"],
        blocking_policies=["p1"],
        requirements=None,
        message="Block msg"
    )
    p1 = PolicyDef(id="p1", description="", when=PolicyConditions(), then=PolicyAction(decision="BLOCKED", message=""))
    
    decision = DecisionFactory.create(mock_ctx, result, [p1])
    
    assert decision.release_status == "BLOCKED"
    assert decision.blocking_policies == ["p1"]
    
def test_decision_factory_conditional(mock_ctx):
    reqs = Requirement(approvals=2, roles=["Dev"])
    result = PolicyResult(
        decision="CONDITIONAL",
        matched_policies=["p2"],
        blocking_policies=[],
        requirements=reqs,
        message="Auth required"
    )
    p2 = PolicyDef(id="p2", description="", when=PolicyConditions(), then=PolicyAction(decision="CONDITIONAL", message=""))
    
    decision = DecisionFactory.create(mock_ctx, result, [p2])
    
    assert decision.release_status == "CONDITIONAL"
