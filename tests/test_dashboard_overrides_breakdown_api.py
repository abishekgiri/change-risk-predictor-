from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _unwrap_dashboard_envelope(response) -> tuple[dict, dict]:
    body = response.json()
    assert body["generated_at"]
    assert body["trace_id"]
    payload = body["data"]
    assert isinstance(payload, dict)
    return body, payload


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _insert_decision(
    *,
    tenant_id: str,
    decision_id: str,
    workflow_id: str,
    transition_id: str,
    policy_id: str,
    policy_version: str,
    created_at: datetime,
) -> None:
    payload = {
        "reason_code": "REQUIRES_OVERRIDE",
        "policy_bindings": [
            {
                "policy_id": policy_id,
                "policy_version": policy_version,
                "policy_hash": f"sha256:{policy_id}:{policy_version}",
            }
        ],
        "input_snapshot": {
            "request": {
                "issue_key": "RG-100",
                "workflow_id": workflow_id,
                "transition_id": transition_id,
                "actor_account_id": "acct-dashboard",
            }
        },
    }
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO audit_decisions (
                tenant_id, decision_id, context_id, repo, pr_number, release_status,
                policy_bundle_hash, engine_version, decision_hash, input_hash, policy_hash,
                replay_hash, full_decision_json, created_at, evaluation_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                decision_id,
                f"context-{decision_id}",
                "org/repo",
                1,
                "BLOCKED",
                "bundle-hash",
                "engine-v1",
                f"decision-hash-{decision_id}",
                f"input-hash-{decision_id}",
                f"sha256:{policy_id}:{policy_version}",
                f"replay-hash-{decision_id}",
                json.dumps(payload, separators=(",", ":"), sort_keys=True),
                created_at.isoformat(),
                f"eval-{decision_id}",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_override(
    *,
    tenant_id: str,
    override_id: str,
    decision_id: str,
    actor: str,
    created_at: datetime,
) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO audit_overrides (
                tenant_id, override_id, decision_id, repo, issue_key, actor,
                reason, target_type, target_id, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                override_id,
                decision_id,
                "org/repo",
                "RG-100",
                actor,
                "manual override",
                "transition",
                "31",
                f"hash-{override_id}",
                created_at.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _seed_override_data(tenant_id: str) -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-a",
        workflow_id="wf-release",
        transition_id="31",
        policy_id="policy.release",
        policy_version="1",
        created_at=now - timedelta(hours=4),
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-b",
        workflow_id="wf-release",
        transition_id="31",
        policy_id="policy.release",
        policy_version="2",
        created_at=now - timedelta(hours=3),
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-c",
        workflow_id="wf-hotfix",
        transition_id="32",
        policy_id="policy.hotfix",
        policy_version="1",
        created_at=now - timedelta(hours=2),
    )

    _insert_override(
        tenant_id=tenant_id,
        override_id="ovr-1",
        decision_id="dec-a",
        actor="alice@example.com",
        created_at=now - timedelta(hours=1),
    )
    _insert_override(
        tenant_id=tenant_id,
        override_id="ovr-2",
        decision_id="dec-b",
        actor="alice@example.com",
        created_at=now - timedelta(hours=2),
    )
    _insert_override(
        tenant_id=tenant_id,
        override_id="ovr-3",
        decision_id="dec-b",
        actor="bob@example.com",
        created_at=now - timedelta(hours=3),
    )
    _insert_override(
        tenant_id=tenant_id,
        override_id="ovr-4",
        decision_id="dec-c",
        actor="carol@example.com",
        created_at=now - timedelta(hours=4),
    )
    from_ts = (now - timedelta(days=1)).isoformat()
    to_ts = now.isoformat()
    return from_ts, to_ts


def test_dashboard_overrides_breakdown_actor_grouping_returns_contract_and_sorted_rows():
    _reset_db()
    tenant_id = "tenant-dashboard-overrides-actor"
    from_ts, to_ts = _seed_override_data(tenant_id)

    response = client.get(
        "/dashboard/overrides/breakdown",
        params={
            "tenant_id": tenant_id,
            "from": from_ts,
            "to": to_ts,
            "group_by": "actor",
            "limit": 25,
        },
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    envelope, body = _unwrap_dashboard_envelope(response)
    assert body["trace_id"] == envelope["trace_id"]
    assert response.headers.get("X-Request-Id") == envelope["trace_id"]
    assert response.headers.get("Cache-Control") == "private, max-age=60"
    assert body["tenant"] == tenant_id
    assert body["group_by"] == "actor"
    assert body["from"] == from_ts
    assert body["to"] == to_ts
    assert body["total_overrides"] == 4
    assert [row["key"] for row in body["rows"]] == [
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
    ]
    assert [row["count"] for row in body["rows"]] == [2, 1, 1]
    assert body["rows"][0]["workflows"] == 1
    assert body["rows"][0]["rules"] == 2
    assert set(body["rows"][0]["sample_override_ids"]) == {"ovr-1", "ovr-2"}


def test_dashboard_overrides_breakdown_supports_workflow_and_rule_grouping():
    _reset_db()
    tenant_id = "tenant-dashboard-overrides-workflow-rule"
    from_ts, to_ts = _seed_override_data(tenant_id)

    workflow_response = client.get(
        "/dashboard/overrides/breakdown",
        params={
            "tenant_id": tenant_id,
            "from": from_ts,
            "to": to_ts,
            "group_by": "workflow",
            "limit": 25,
        },
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert workflow_response.status_code == 200, workflow_response.text
    _, workflow_body = _unwrap_dashboard_envelope(workflow_response)
    assert workflow_body["group_by"] == "workflow"
    assert [row["key"] for row in workflow_body["rows"]] == ["wf-release", "wf-hotfix"]
    assert [row["count"] for row in workflow_body["rows"]] == [3, 1]
    assert workflow_body["rows"][0]["actors"] == 2
    assert workflow_body["rows"][0]["rules"] == 2

    rule_response = client.get(
        "/dashboard/overrides/breakdown",
        params={
            "tenant_id": tenant_id,
            "from": from_ts,
            "to": to_ts,
            "group_by": "rule",
            "limit": 25,
        },
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert rule_response.status_code == 200, rule_response.text
    _, rule_body = _unwrap_dashboard_envelope(rule_response)
    assert rule_body["group_by"] == "rule"
    assert [row["key"] for row in rule_body["rows"]] == [
        "policy.release:2",
        "policy.hotfix:1",
        "policy.release:1",
    ]
    assert [row["count"] for row in rule_body["rows"]] == [2, 1, 1]
    assert rule_body["rows"][0]["actors"] == 2
    assert rule_body["rows"][0]["workflows"] == 1


def test_dashboard_overrides_breakdown_validates_group_by():
    _reset_db()
    tenant_id = "tenant-dashboard-overrides-validation"
    from_ts = "2026-03-01T00:00:00+00:00"
    to_ts = "2026-03-04T00:00:00+00:00"

    response = client.get(
        "/dashboard/overrides/breakdown",
        params={
            "tenant_id": tenant_id,
            "from": from_ts,
            "to": to_ts,
            "group_by": "invalid",
        },
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 400
    body = response.json()
    assert body["generated_at"]
    assert body["trace_id"]
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["error_code"] == "VALIDATION_ERROR"
