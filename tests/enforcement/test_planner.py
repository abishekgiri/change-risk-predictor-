import pytest
from releasegate.enforcement.planner import EnforcementPlanner
from releasegate.decision.types import Decision, EnforcementTargets
from datetime import datetime

def test_planner_decoupled():
    """Verify planner works with ONLY a Decision object."""
    decision = Decision(
        timestamp=datetime.now(),
        decision_id="d1",
        release_status="BLOCKED",
        matched_policies=[],
        blocking_policies=[],
        policy_bundle_hash="h",
        context_id="c1",
        message="Blocked msg",
        enforcement_targets=EnforcementTargets(
            repository="owner/repo",
            ref="sha123",
            pr_number=99
        )
    )
    
    actions = EnforcementPlanner.plan(decision)
    # expect 1 action (GitHub Check)
    assert len(actions) == 1
    
    action = actions[0]
    assert action.action_type == "GITHUB_CHECK"
    assert action.target == "owner/repo"
    assert action.payload["head_sha"] == "sha123"
    assert action.payload["conclusion"] == "failure"
    assert "Blocked msg" in action.payload["output"]["summary"]
