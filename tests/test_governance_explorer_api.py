from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

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


def _seed_decision(
    *,
    tenant_id: str,
    decision_id: str,
    created_at: datetime,
    release_status: str,
    issue_key: str,
    transition_id: str,
    actor: str,
    workflow_id: str,
    environment: str,
    project_key: str,
    risk_score: float,
    risk_level: str,
    override_used: bool,
) -> None:
    payload = {
        "decision_id": decision_id,
        "release_status": release_status,
        "policy_bindings": [
            {
                "policy_id": "SEC-1",
                "policy_version": "1",
                "policy_hash": "sha256:policy",
            }
        ],
        "input_snapshot": {
            "request": {
                "issue_key": issue_key,
                "transition_id": transition_id,
                "actor_account_id": actor,
                "source_status": "In Progress",
                "target_status": "Done",
                "environment": environment,
                "project_key": project_key,
                "context_overrides": {"workflow_id": workflow_id},
            },
            "risk_meta": {
                "risk_score": risk_score,
                "risk_level": risk_level,
            },
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
                f"ctx-{decision_id}",
                "org/repo",
                1,
                release_status,
                "bundle-hash",
                "engine-v1",
                f"decision-{decision_id}",
                f"input-{decision_id}",
                "policy-hash",
                f"replay-{decision_id}",
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                created_at.isoformat(),
                f"eval-{decision_id}",
            ),
        )
        conn.execute(
            """
            INSERT INTO decision_transition_links (
                tenant_id, decision_id, jira_issue_id, transition_id, actor,
                source_status, target_status, policy_id, policy_version, policy_hash,
                context_hash, expires_at, consumed, consumed_at, consumed_by_request_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                decision_id,
                issue_key,
                transition_id,
                actor,
                "In Progress",
                "Done",
                "SEC-1",
                1,
                "policy-hash",
                f"context-{decision_id}",
                (created_at + timedelta(hours=1)).isoformat(),
                0,
                None,
                None,
                created_at.isoformat(),
            ),
        )
        if override_used:
            conn.execute(
                """
                INSERT INTO audit_overrides (
                    tenant_id, override_id, decision_id, repo, pr_number, issue_key, actor,
                    reason, target_type, target_id, idempotency_key, previous_hash, event_hash,
                    ttl_seconds, expires_at, requested_by, approved_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    f"ovr-{decision_id}",
                    decision_id,
                    "org/repo",
                    1,
                    issue_key,
                    actor,
                    "manual override",
                    "issue",
                    issue_key,
                    f"idem-{decision_id}",
                    "",
                    f"event-hash-{decision_id}",
                    3600,
                    (created_at + timedelta(hours=1)).isoformat(),
                    actor,
                    "approver",
                    created_at.isoformat(),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def test_governance_decision_explorer_filters():
    _reset_db()
    tenant_id = "tenant-governance-query"
    now = datetime.now(timezone.utc)

    _seed_decision(
        tenant_id=tenant_id,
        decision_id="d-1",
        created_at=now - timedelta(minutes=30),
        release_status="ALLOWED",
        issue_key="RG-1",
        transition_id="31",
        actor="acct-1",
        workflow_id="wf-release",
        environment="prod",
        project_key="ABC",
        risk_score=0.91,
        risk_level="HIGH",
        override_used=True,
    )
    _seed_decision(
        tenant_id=tenant_id,
        decision_id="d-2",
        created_at=now - timedelta(minutes=20),
        release_status="BLOCKED",
        issue_key="RG-2",
        transition_id="41",
        actor="acct-2",
        workflow_id="wf-hotfix",
        environment="staging",
        project_key="XYZ",
        risk_score=0.22,
        risk_level="LOW",
        override_used=False,
    )
    _seed_decision(
        tenant_id=tenant_id,
        decision_id="d-3",
        created_at=now - timedelta(minutes=10),
        release_status="ALLOWED",
        issue_key="RG-3",
        transition_id="31",
        actor="acct-1",
        workflow_id="wf-release",
        environment="prod",
        project_key="ABC",
        risk_score=0.73,
        risk_level="HIGH",
        override_used=False,
    )

    resp = client.get(
        "/governance/decisions",
        params={
            "tenant_id": tenant_id,
            "risk_min": 0.7,
                "actor": "acct-1",
                "workflow_id": "wf-release",
                "decision_status": "ALLOWED",
                "limit": 500,
            },
            headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
        )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["tenant_id"] == tenant_id
    ids = [item["decision_id"] for item in payload["results"]]
    assert ids == ["d-3", "d-1"]
    assert all(float(item["risk_score"]) >= 0.7 for item in payload["results"])
    assert all(item["actor"] == "acct-1" for item in payload["results"])

    invalid_limit = client.get(
        "/governance/decisions",
        params={"tenant_id": tenant_id, "limit": 1000},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert invalid_limit.status_code == 400

    override_resp = client.get(
        "/governance/decisions",
        params={"tenant_id": tenant_id, "override_used": True, "limit": 100},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert override_resp.status_code == 200
    override_items = override_resp.json()["results"]
    assert [row["decision_id"] for row in override_items] == ["d-1"]


def test_governance_decision_explorer_cursor_pagination_stable():
    _reset_db()
    tenant_id = "tenant-governance-cursor"
    now = datetime.now(timezone.utc)

    for index in range(3):
        _seed_decision(
            tenant_id=tenant_id,
            decision_id=f"d-{index}",
            created_at=now - timedelta(minutes=(3 - index)),
            release_status="ALLOWED",
            issue_key=f"RG-{index}",
            transition_id="31",
            actor="acct-cursor",
            workflow_id="wf-release",
            environment="prod",
            project_key="ABC",
            risk_score=0.8,
            risk_level="HIGH",
            override_used=False,
        )

    first = client.get(
        "/governance/decisions",
        params={"tenant_id": tenant_id, "limit": 1},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    first_ids = [row["decision_id"] for row in first_body["results"]]
    assert len(first_ids) == 1
    assert first_body["next_cursor"]

    second = client.get(
        "/governance/decisions",
        params={"tenant_id": tenant_id, "limit": 1, "cursor": first_body["next_cursor"]},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    second_ids = [row["decision_id"] for row in second_body["results"]]
    assert len(second_ids) == 1
    assert second_ids[0] != first_ids[0]


def test_governance_decision_explorer_cross_tenant_forbidden():
    _reset_db()
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    now = datetime.now(timezone.utc)

    _seed_decision(
        tenant_id=tenant_a,
        decision_id=f"d-{uuid.uuid4().hex[:6]}",
        created_at=now,
        release_status="ALLOWED",
        issue_key="RG-9",
        transition_id="31",
        actor="acct",
        workflow_id="wf",
        environment="prod",
        project_key="ABC",
        risk_score=0.5,
        risk_level="MEDIUM",
        override_used=False,
    )

    denied = client.get(
        "/governance/decisions",
        params={"tenant_id": tenant_a},
        headers=jwt_headers(tenant_id=tenant_b, scopes=["policy:read"]),
    )
    assert denied.status_code == 403
