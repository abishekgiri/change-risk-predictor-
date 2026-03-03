from __future__ import annotations

import os

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def test_dashboard_policy_diff_returns_visual_sections():
    _reset_db()
    tenant_id = "tenant-policy-diff-visual"
    current_policy = {
        "strict_fail_closed": True,
        "approval_requirements": {"min_approvals": 2, "required_roles": ["security", "em"]},
        "protected_statuses": ["Done", "Released"],
        "risk_thresholds": {"prod": {"max_score": 0.7}},
        "transition_rules": [
            {
                "rule_id": "prod-block",
                "transition_id": "31",
                "environment": "prod",
                "result": "BLOCK",
                "priority": 100,
            }
        ],
    }
    candidate_policy = {
        "strict_fail_closed": False,
        "approval_requirements": {"min_approvals": 1, "required_roles": ["security"]},
        "protected_statuses": ["Released"],
        "risk_thresholds": {"prod": {"max_score": 0.9}},
        "transition_rules": [
            {
                "rule_id": "prod-block",
                "transition_id": "31",
                "environment": "prod",
                "result": "ALLOW",
                "priority": 100,
            }
        ],
    }

    response = client.post(
        "/dashboard/policies/diff",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
        json={
            "tenant_id": tenant_id,
            "current_policy_json": current_policy,
            "candidate_policy_json": candidate_policy,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["overall"] == "WEAKENING"
    assert body["summary"]["warning_count"] >= 1
    assert len(body["threshold_deltas"]) >= 1
    assert len(body["condition_deltas"]) >= 1
    assert len(body["role_deltas"]) == 1
    assert "active_policy" in body
    assert "staged_policy" in body
