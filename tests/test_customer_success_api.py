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


def _unwrap_dashboard_envelope(response) -> tuple[dict, dict]:
    body = response.json()
    assert body["generated_at"]
    assert body["trace_id"]
    payload = body["data"]
    assert isinstance(payload, dict)
    return body, payload


def _insert_decision(
    *,
    tenant_id: str,
    decision_id: str,
    created_at: datetime,
    release_status: str,
    risk_score: float,
    workflow_id: str = "wf-release",
) -> None:
    payload = {
        "reason_code": "RISK_POLICY",
        "input_snapshot": {
            "request": {
                "issue_key": f"RG-{decision_id}",
                "transition_id": "31",
                "actor_account_id": "acct-risk",
                "environment": "prod",
                "project_key": "PROJ",
                "context_overrides": {"workflow_id": workflow_id},
            },
            "risk_meta": {
                "risk_score": risk_score,
                "risk_level": "HIGH" if risk_score >= 0.7 else "LOW",
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


def _insert_override(*, tenant_id: str, override_id: str, decision_id: str, actor: str, created_at: datetime) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO audit_overrides (
                tenant_id, override_id, repo, pr_number, issue_key, decision_id,
                actor, reason, target_type, target_id, idempotency_key,
                previous_hash, event_hash, ttl_seconds, expires_at, requested_by,
                approved_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                override_id,
                "org/repo",
                1,
                f"RG-{decision_id}",
                decision_id,
                actor,
                "Emergency override",
                "transition",
                "31",
                f"idem-{override_id}",
                f"prev-hash-{override_id}",
                f"event-hash-{override_id}",
                3600,
                (created_at + timedelta(hours=1)).isoformat(),
                actor,
                "acct-admin",
                created_at.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_rollup(*, tenant_id: str, date_utc: str, integrity_score: float, drift_index: float) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO governance_daily_metrics (
                tenant_id, date_utc, integrity_score, drift_index, override_rate, blocked_count,
                strict_mode_count, override_count, decision_count, computed_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                date_utc,
                integrity_score,
                drift_index,
                0.0,
                0,
                0,
                0,
                0,
                datetime.now(timezone.utc).isoformat(),
                "{}",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_policy_event(
    *,
    tenant_id: str,
    event_id: str,
    policy_id: str,
    event_type: str,
    created_at: datetime,
    scope_type: str = "workflow",
    scope_id: str = "deploy-prod",
) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO policy_registry_events (
                tenant_id, event_id, policy_id, event_type, actor_id, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                event_id,
                policy_id,
                event_type,
                "acct-admin",
                json.dumps({"scope_type": scope_type, "scope_id": scope_id}),
                created_at.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_customer_success_risk_trend_and_override_analysis():
    _reset_db()
    tenant_id = "tenant-cs-risk"
    now = datetime.now(timezone.utc)
    day_one = now - timedelta(days=2)
    day_two = now - timedelta(days=1)

    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-risk-1",
        created_at=day_one,
        release_status="BLOCKED",
        risk_score=0.90,
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-risk-2",
        created_at=day_one + timedelta(minutes=10),
        release_status="ALLOWED",
        risk_score=0.80,
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-risk-3",
        created_at=day_two,
        release_status="ALLOWED",
        risk_score=0.30,
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-risk-4",
        created_at=day_two + timedelta(minutes=10),
        release_status="ALLOWED",
        risk_score=0.20,
    )

    _insert_override(
        tenant_id=tenant_id,
        override_id="ovr-risk-1",
        decision_id="dec-risk-2",
        actor="alice",
        created_at=day_one + timedelta(minutes=15),
    )

    risk_response = client.get(
        "/dashboard/customer_success/risk_trend",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert risk_response.status_code == 200, risk_response.text
    _, risk_payload = _unwrap_dashboard_envelope(risk_response)
    assert len(risk_payload["risk_index"]) >= 2
    assert risk_payload["risk_delta_30d"] < 0
    assert risk_payload["release_stability_delta"] > 0

    override_response = client.get(
        "/dashboard/customer_success/override_analysis",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert override_response.status_code == 200, override_response.text
    _, override_payload = _unwrap_dashboard_envelope(override_response)
    assert override_payload["total_overrides"] == 1
    assert override_payload["top_users"][0]["user"] == "alice"


def test_customer_success_override_concentration_and_weakening_signal():
    _reset_db()
    tenant_id = "tenant-cs-overrides"
    now = datetime.now(timezone.utc)

    for index in range(20):
        _insert_decision(
            tenant_id=tenant_id,
            decision_id=f"dec-base-{index}",
            created_at=now - timedelta(days=25) + timedelta(hours=index),
            release_status="ALLOWED",
            risk_score=0.4,
        )
    _insert_override(
        tenant_id=tenant_id,
        override_id="ovr-base-1",
        decision_id="dec-base-1",
        actor="alice",
        created_at=now - timedelta(days=24),
    )

    for index in range(20):
        _insert_decision(
            tenant_id=tenant_id,
            decision_id=f"dec-recent-{index}",
            created_at=now - timedelta(days=3) + timedelta(hours=index),
            release_status="ALLOWED",
            risk_score=0.5,
        )
    for index in range(8):
        _insert_override(
            tenant_id=tenant_id,
            override_id=f"ovr-recent-alice-{index}",
            decision_id=f"dec-recent-{index}",
            actor="alice",
            created_at=now - timedelta(days=2) + timedelta(hours=index),
        )
    for index in range(2):
        _insert_override(
            tenant_id=tenant_id,
            override_id=f"ovr-recent-bob-{index}",
            decision_id=f"dec-recent-{index + 8}",
            actor="bob",
            created_at=now - timedelta(days=2) + timedelta(hours=index + 8),
        )

    response = client.get(
        "/dashboard/customer_success/override_analysis",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    _, payload = _unwrap_dashboard_envelope(response)
    assert payload["top_users"][0]["user"] == "alice"
    assert payload["override_concentration_index"] > 0.6
    assert payload["policy_weakening_signal"] is True
    assert payload["override_rate_recent"] > payload["override_rate_baseline"]


def test_customer_success_regression_report_detects_integrity_drop():
    _reset_db()
    tenant_id = "tenant-cs-regression"
    now = datetime.now(timezone.utc)
    policy_event_time = now - timedelta(days=3)

    _insert_rollup(tenant_id=tenant_id, date_utc=(policy_event_time - timedelta(days=2)).date().isoformat(), integrity_score=96.0, drift_index=0.01)
    _insert_rollup(tenant_id=tenant_id, date_utc=(policy_event_time - timedelta(days=1)).date().isoformat(), integrity_score=94.0, drift_index=0.01)
    _insert_rollup(tenant_id=tenant_id, date_utc=(policy_event_time + timedelta(days=1)).date().isoformat(), integrity_score=81.0, drift_index=0.05)
    _insert_rollup(tenant_id=tenant_id, date_utc=(policy_event_time + timedelta(days=2)).date().isoformat(), integrity_score=79.0, drift_index=0.06)

    _insert_policy_event(
        tenant_id=tenant_id,
        event_id="evt-policy-1",
        policy_id="policy-1",
        event_type="POLICY_ACTIVATED",
        created_at=policy_event_time,
        scope_type="workflow",
        scope_id="deploy-prod",
    )

    response = client.get(
        "/dashboard/customer_success/regression_report",
        params={
            "tenant_id": tenant_id,
            "window_days": 30,
            "correlation_window_hours": 48,
            "drop_threshold": 10.0,
        },
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    _, payload = _unwrap_dashboard_envelope(response)
    assert payload["total_policy_changes"] >= 1
    assert payload["regressions_detected"] >= 1
    regression = payload["regressions"][0]
    assert regression["policy_change_id"] == "evt-policy-1"
    assert regression["integrity_drop"] >= 10.0
    assert "deploy-prod" in regression["affected_workflows"]
