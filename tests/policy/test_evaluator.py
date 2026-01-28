import pytest
from releasegate.policy.types import PolicyDef, PolicyConditions, PolicyAction, Requirement, Predicate
from releasegate.policy.evaluator import PolicyEvaluator
from releasegate.context.types import EvaluationContext, Actor, Change, Timing
from releasegate.context.builder import ContextBuilder

@pytest.fixture
def mock_context():
    return (ContextBuilder()
            .with_actor("u1", "login1")
            .with_change("o/r", "1", ["f1.py"], change_type="PR", lines_changed=100)
            .with_environment("PRODUCTION")
            .build())

@pytest.fixture
def evaluator():
    return PolicyEvaluator()

def test_evaluator_no_matches(evaluator, mock_context):
    result = evaluator.evaluate(mock_context, [])
    assert result.decision == "ALLOWED"

def test_evaluator_block_wins(evaluator, mock_context):
    p1 = PolicyDef(
        id="allow-rule", description="Allow", priority=10,
        when=PolicyConditions(), # Matches everything
        then=PolicyAction(decision="ALLOWED", message="OK")
    )
    p2 = PolicyDef(
        id="block-rule", description="Block", priority=5,
        when=PolicyConditions(environment=Predicate(eq="PRODUCTION")),
        then=PolicyAction(decision="BLOCKED", message="Blocked!")
    )
    
    result = evaluator.evaluate(mock_context, [p1, p2])
    assert result.decision == "BLOCKED"
    assert "block-rule" in result.blocking_policies
    assert result.message == "Blocked!" # Priority 5 vs 10

def test_requirements_merge(evaluator, mock_context):
    # Two conditional policies
    p1 = PolicyDef(
        id="c1", description="C1", priority=10,
        when=PolicyConditions(),
        then=PolicyAction(decision="CONDITIONAL", requires=Requirement(approvals=1, roles=["Dev"]), message="C1")
    )
    p2 = PolicyDef(
        id="c2", description="C2", priority=10,
        when=PolicyConditions(),
        then=PolicyAction(decision="CONDITIONAL", requires=Requirement(approvals=2, roles=["Sec"]), message="C2")
    )
    
    result = evaluator.evaluate(mock_context, [p1, p2])
    assert result.decision == "CONDITIONAL"
    assert result.requirements.approvals == 2 # Max
    assert set(result.requirements.roles) == {"Dev", "Sec"} # Union

def test_operators(evaluator):
    # Test operators manually
    ctx = (ContextBuilder().with_actor("u","l").with_change("r","1",[],lines_changed=50).build())
    ctx.signals["risk"] = 80
    
    p = PolicyDef(
        id="op-test", description="Ops",
        when=PolicyConditions(
            signals={"risk": Predicate(gt=60)},
            context={"change.lines_changed": Predicate(lte=50)}
        ),
        then=PolicyAction(decision="BLOCKED", message="Hit")
    )
    
    assert evaluator.evaluate(ctx, [p]).decision == "BLOCKED"
    
    # Fail condition
    ctx.signals["risk"] = 50
    assert evaluator.evaluate(ctx, [p]).decision == "ALLOWED"

def test_dot_path_lookup(evaluator):
    ctx = (ContextBuilder()
           .with_actor("u","l")
           .with_change("r","1",[], change_type="PR")
           .build())
    # Manually check helper
    assert evaluator._get_context_value(ctx, "change.change_type") == "PR"
    assert evaluator._get_context_value(ctx, "actor.login") == "l"
