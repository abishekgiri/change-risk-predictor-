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


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _insert_active_transition_policy(*, tenant_id: str, transition_id: str = "31") -> None:
    policy_json = {
        "strict_fail_closed": True,
        "transition_rules": [
            {
                "transition_id": transition_id,
                "result": "BLOCK",
                "priority": 1,
            }
        ],
    }
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO policy_registry_entries (
                tenant_id, policy_id, scope_type, scope_id, version, status,
                policy_json, policy_hash, lint_errors_json, lint_warnings_json,
                rollout_percentage, rollout_scope, created_at, created_by,
                activated_at, activated_by, supersedes_policy_id, archived_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', 100, NULL, ?, 'tests', ?, 'tests', NULL, NULL)
            """,
            (
                tenant_id,
                f"policy-{transition_id}",
                "transition",
                transition_id,
                1,
                "ACTIVE",
                json.dumps(policy_json, separators=(",", ":"), sort_keys=True),
                f"sha256:policy-{transition_id}",
                now,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_decision(
    *,
    tenant_id: str,
    decision_id: str,
    transition_id: str,
    risk_level: str,
    created_at: datetime,
) -> None:
    payload = {
        "release_status": "ALLOWED",
        "reason_code": "TEST",
        "input_snapshot": {
            "request": {
                "issue_key": f"SIM-{decision_id}",
                "transition_id": transition_id,
                "actor_account_id": "acct-sim",
                "environment": "prod",
                "project_key": "PAYMENTS",
                "context_overrides": {"workflow_id": "wf-release"},
            },
            "signal_map": {
                "risk": {"level": risk_level},
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
                f"context-{decision_id}",
                "org/repo",
                1,
                "ALLOWED",
                "bundle-hash",
                "engine-v1",
                f"decision-hash-{decision_id}",
                f"input-hash-{decision_id}",
                "policy-hash",
                f"replay-hash-{decision_id}",
                json.dumps(payload, separators=(",", ":"), sort_keys=True),
                created_at.isoformat(),
                f"eval-{decision_id}",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _count_table_rows(*, table: str, tenant_id: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            f"SELECT COUNT(1) FROM {table} WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        return int(row[0] or 0) if row else 0
    finally:
        conn.close()


def _unwrap_envelope(response) -> dict:
    body = response.json()
    assert body.get("generated_at")
    assert body.get("trace_id")
    assert isinstance(body.get("data"), dict)
    return body["data"]


def test_simulation_run_returns_expected_metrics_and_no_policy_side_effects():
    _reset_db()
    tenant_id = "tenant-sim-run"
    _insert_active_transition_policy(tenant_id=tenant_id, transition_id="31")
    now = datetime.now(timezone.utc)
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-1",
        transition_id="31",
        risk_level="HIGH",
        created_at=now - timedelta(days=2),
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-2",
        transition_id="50",
        risk_level="MEDIUM",
        created_at=now - timedelta(days=1),
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-3",
        transition_id="31",
        risk_level="LOW",
        created_at=now - timedelta(hours=1),
    )

    response = client.post(
        "/simulation/run",
        headers=jwt_headers(
            tenant_id=tenant_id,
            scopes=["policy:read"],
        ),
        json={"tenant_id": tenant_id, "lookback_days": 30},
    )
    assert response.status_code == 200
    payload = _unwrap_envelope(response)

    assert payload["tenant_id"] == tenant_id
    assert payload["lookback_days"] == 30
    assert payload["total_transitions"] == 3
    assert payload["blocked"] == 2
    assert payload["allowed"] == 1
    assert payload["blocked_pct"] == 66.67
    assert payload["override_required"] == 2
    assert payload["risk_distribution"] == {"low": 1, "medium": 1, "high": 1}
    assert payload["has_run"] is True
    assert payload["ran_at"]

    assert _count_table_rows(table="policy_simulation_events", tenant_id=tenant_id) == 0
    assert _count_table_rows(table="audit_overrides", tenant_id=tenant_id) == 0
    assert _count_table_rows(table="tenant_simulation_runs", tenant_id=tenant_id) == 1


def test_simulation_last_returns_last_persisted_run():
    _reset_db()
    tenant_id = "tenant-sim-last"
    _insert_active_transition_policy(tenant_id=tenant_id, transition_id="31")
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-last-1",
        transition_id="31",
        risk_level="HIGH",
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
    )

    run_response = client.post(
        "/simulation/run",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
        json={"tenant_id": tenant_id, "lookback_days": 30},
    )
    assert run_response.status_code == 200
    run_payload = _unwrap_envelope(run_response)

    last_response = client.get(
        "/simulation/last",
        params={"tenant_id": tenant_id, "lookback_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert last_response.status_code == 200
    last_payload = _unwrap_envelope(last_response)

    assert last_payload["has_run"] is True
    assert last_payload["tenant_id"] == tenant_id
    assert last_payload["total_transitions"] == run_payload["total_transitions"]
    assert last_payload["blocked"] == run_payload["blocked"]
    assert last_payload["override_required"] == run_payload["override_required"]


def test_simulation_last_is_tenant_isolated():
    _reset_db()
    tenant_a = "tenant-sim-a"
    tenant_b = "tenant-sim-b"
    _insert_active_transition_policy(tenant_id=tenant_a, transition_id="31")
    _insert_decision(
        tenant_id=tenant_a,
        decision_id="dec-a",
        transition_id="31",
        risk_level="HIGH",
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )

    response = client.post(
        "/simulation/run",
        headers=jwt_headers(tenant_id=tenant_a, scopes=["policy:read"]),
        json={"tenant_id": tenant_a, "lookback_days": 30},
    )
    assert response.status_code == 200

    other_response = client.get(
        "/simulation/last",
        params={"tenant_id": tenant_b, "lookback_days": 30},
        headers=jwt_headers(tenant_id=tenant_b, scopes=["policy:read"]),
    )
    assert other_response.status_code == 200
    payload = _unwrap_envelope(other_response)
    assert payload["tenant_id"] == tenant_b
    assert payload["has_run"] is False
    assert payload["total_transitions"] == 0
    assert payload["blocked"] == 0


def test_simulation_run_requires_supported_role():
    _reset_db()
    tenant_id = "tenant-sim-scope"
    response = client.post(
        "/simulation/run",
        headers=jwt_headers(
            tenant_id=tenant_id,
            roles=["guest"],
            scopes=["policy:read"],
        ),
        json={"tenant_id": tenant_id, "lookback_days": 30},
    )
    assert response.status_code == 403
