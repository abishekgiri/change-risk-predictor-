import pytest
import sqlite3
import os
import json
from datetime import datetime, timezone
from releasegate.audit.recorder import AuditRecorder
from releasegate.audit.reader import AuditReader
from releasegate.decision.types import Decision, EnforcementTargets
from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db

@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

def test_audit_recording(clean_db):
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id="c1",
        message="OK",
        policy_bundle_hash="hash1",
        enforcement_targets=EnforcementTargets(repository="repo1", ref="HEAD")
    )
    
    AuditRecorder.record_with_context(decision, repo="repo1", pr_number=101)
    
    # Verify in DB directly
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_decisions WHERE decision_id = ?", (decision.decision_id,))
    row = cursor.fetchone()
    conn.close()
    
    assert row is not None
    assert row["repo"] == "repo1"
    assert row["pr_number"] == 101
    assert row["policy_bundle_hash"] == "hash1"
    assert row["engine_version"] == "0.2.0"
    assert row["decision_hash"] is not None

def test_audit_query(clean_db):
    # Insert decisions
    for i in range(3):
        d = Decision(
            timestamp=datetime.now(timezone.utc),
            release_status="BLOCKED" if i == 0 else "ALLOWED",
            context_id=f"c{i}",
            message="msg",
            enforcement_targets=EnforcementTargets(repository="target-repo", pr_number=i, ref="HEAD")
        )
        AuditRecorder.record_with_context(d, repo="target-repo", pr_number=i)
        
    # Test List
    results = AuditReader.list_decisions(repo="target-repo")
    assert len(results) == 3
    
    # Test Filter
    blocked = AuditReader.list_decisions(repo="target-repo", status="BLOCKED")
    assert len(blocked) == 1
    assert blocked[0]["pr_number"] == 0

    # Test Show
    d_last = results[0] # Should be latest date due to order by desc? 
    # Actually timestamp string sort: 03 > 02 > 01. 
    # results[0] is most recent.
    
    full = AuditReader.get_decision(d_last["decision_id"])
    assert full["full_decision_json"] is not None
    assert "ALLOWED" in full["full_decision_json"]
