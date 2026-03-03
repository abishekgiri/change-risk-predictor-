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
    assert body["summary"]["has_changes"] is True
    assert body["summary"]["change_count"] >= 1
    assert body["summary"]["warning_count"] >= 1
    assert body["summary"]["severity_counts"]["high"] >= 1
    assert body["summary"]["summary_bullets"]
    assert len(body["threshold_deltas"]) >= 1
    assert len(body["condition_deltas"]) >= 1
    assert len(body["role_deltas"]) >= 1
    assert all(delta.get("severity") in {"low", "medium", "high"} for delta in body["threshold_deltas"])
    assert all(delta.get("severity") in {"low", "medium", "high"} for delta in body["condition_deltas"])
    assert all(delta.get("severity") in {"low", "medium", "high"} for delta in body["role_deltas"])
    assert all(delta.get("severity") in {"low", "medium", "high"} for delta in body["sod_deltas"])
    # deterministic ordering: high severity should appear before low severity in each delta bucket.
    rank = {"high": 0, "medium": 1, "low": 2}
    for bucket in ("threshold_deltas", "condition_deltas", "role_deltas", "sod_deltas"):
        severities = [rank[item["severity"]] for item in body[bucket]]
        assert severities == sorted(severities)
    assert "active_policy" in body
    assert "staged_policy" in body
