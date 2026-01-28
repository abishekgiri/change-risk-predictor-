import pytest
import sqlite3
from datetime import datetime, timezone
from releasegate.audit.reader import AuditReader
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets
from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db

@pytest.fixture
def clean_db():
    init_db()
    yield
    # Cleanup if needed

def test_idempotency(clean_db):
    """Test that duplicate evaluations reuse the existing decision."""
    
    # 1. Create a decision
    d1 = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id="c1",
        message="ok",
        policy_bundle_hash="h1",
        evaluation_key="key1",
        enforcement_targets=EnforcementTargets(repository="r", ref="sha")
    )
    
    # 2. Record it
    AuditRecorder.record_with_context(d1, "r", 1)
    
    # 3. Try fetch by key
    stored = AuditReader.get_decision_by_evaluation_key("key1")
    assert stored is not None
    assert stored["decision_id"] == d1.decision_id
    
    # 4. Verify uniqueness constraint
    # Trying to reuse the same KEY with different ID should fail at SQL level
    d2 = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id="c2",
        message="ok",
        policy_bundle_hash="h1",
        evaluation_key="key1", # DUPLICATE KEY
        enforcement_targets=EnforcementTargets(repository="r", ref="sha")
    )
    
    try:
        AuditRecorder.record_with_context(d2, "r", 1)
        pytest.fail("Should have raised IntegrityError (Unique Constraint)")
    except sqlite3.IntegrityError:
        pass # Expected

def test_planner_blocked(clean_db):
    """Test that blocked decisions generate proper actions."""
    from releasegate.enforcement.planner import EnforcementPlanner
    
    d = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id="c_blocked",
        message="Blocked by policy",
        blocking_policies=["policy-123"],
        policy_bundle_hash="h2",
        enforcement_targets=EnforcementTargets(repository="r", ref="sha")
    )
    
    actions = EnforcementPlanner.plan(d)
    assert len(actions) == 1
    assert actions[0].action_type == "GITHUB_CHECK"
    assert actions[0].payload["conclusion"] == "failure"
