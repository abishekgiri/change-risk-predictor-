from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from releasegate.audit.reader import AuditReader
from releasegate.audit.recorder import AuditRecorder
from releasegate.config import DB_PATH
from releasegate.decision.types import Decision, DecisionType, EnforcementTargets, ExternalKeys
from releasegate.storage import get_storage_backend
from releasegate.storage.schema import init_db


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def test_audit_recorder_writes_decision_refs_and_searches_by_jira(clean_db):
    tenant = "tenant-a"
    repo = "org/repo"
    pr_number = 42
    issue_key = "PROJ-123"

    decision = Decision(
        tenant_id=tenant,
        timestamp=datetime.now(timezone.utc),
        release_status=DecisionType.ALLOWED,
        context_id="ctx-1",
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="abc123",
            external=ExternalKeys(jira=[issue_key]),
        ),
        message="ok",
    )
    AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number, tenant_id=tenant)

    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT ref_type, ref_value
        FROM audit_decision_refs
        WHERE tenant_id = ? AND decision_id = ? AND ref_type = ? AND ref_value = ?
        """,
        (tenant, decision.decision_id, "jira", issue_key),
    )
    assert row is not None
    assert row["ref_type"] == "jira"
    assert row["ref_value"] == issue_key

    results = AuditReader.search_decisions(
        tenant_id=tenant,
        jira_issue_key=issue_key,
        limit=10,
    )
    assert any(r.get("decision_id") == decision.decision_id for r in results)

    with pytest.raises(Exception):
        storage.execute(
            "UPDATE audit_decision_refs SET ref_value = ? WHERE tenant_id = ? AND decision_id = ?",
            ("MUT", tenant, decision.decision_id),
        )
    with pytest.raises(Exception):
        storage.execute(
            "DELETE FROM audit_decision_refs WHERE tenant_id = ? AND decision_id = ?",
            (tenant, decision.decision_id),
        )
