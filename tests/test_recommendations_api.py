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


def _insert_decision(
    *,
    tenant_id: str,
    decision_id: str,
    policy_hash: str,
    release_status: str,
    reason_code: str,
    created_at: datetime,
) -> None:
    payload = {
        "reason_code": reason_code,
        "input_snapshot": {
            "request": {
                "issue_key": f"RG-{decision_id}",
                "transition_id": "31",
                "actor_account_id": "acct-policy",
                "environment": "prod",
                "project_key": "PAY",
                "context_overrides": {"workflow_id": "wf-release"},
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
                f"ctx-{decision_id}",
                "org/repo",
                1,
                release_status,
                "bundle-hash",
                "engine-v1",
                f"decision-hash-{decision_id}",
                f"input-hash-{decision_id}",
                policy_hash,
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
                "RG-100",
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


def test_reco_override_spike_generates_playbook():
    _reset_db()
    tenant_id = "tenant-reco-override"
    now = datetime.now(timezone.utc)
    for index in range(12):
        _insert_decision(
            tenant_id=tenant_id,
            decision_id=f"dec-override-{index}",
            policy_hash="policy-1",
            release_status="ALLOWED",
            reason_code="APPROVED",
            created_at=now - timedelta(hours=index),
        )
    for index in range(6):
        _insert_override(
            tenant_id=tenant_id,
            override_id=f"ovr-override-{index}",
            decision_id=f"dec-override-{index}",
            actor="alice",
            created_at=now - timedelta(hours=index),
        )

    response = client.get(
        "/governance/recommendations",
        params={"tenant_id": tenant_id, "refresh": True, "lookback_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    recommendation_types = {item["recommendation_type"] for item in payload["recommendations"]}
    assert "OVERRIDE_SPIKE" in recommendation_types
    override_item = next(item for item in payload["recommendations"] if item["recommendation_type"] == "OVERRIDE_SPIKE")
    assert override_item["playbook"]


def test_reco_policy_drift_detected_on_threshold():
    _reset_db()
    tenant_id = "tenant-reco-drift"
    now = datetime.now(timezone.utc)
    for index in range(10):
        _insert_decision(
            tenant_id=tenant_id,
            decision_id=f"dec-drift-{index}",
            policy_hash="policy-a" if index < 5 else "policy-b",
            release_status="BLOCKED" if index < 3 else "ALLOWED",
            reason_code="POLICY_BLOCKED" if index < 3 else "APPROVED",
            created_at=now - timedelta(hours=index),
        )

    response = client.get(
        "/governance/recommendations",
        params={"tenant_id": tenant_id, "refresh": True, "lookback_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    recommendation_types = {item["recommendation_type"] for item in payload["recommendations"]}
    assert "POLICY_DRIFT" in recommendation_types


def test_reco_missing_signals_generates_action():
    _reset_db()
    tenant_id = "tenant-reco-missing-signals"
    now = datetime.now(timezone.utc)
    for index in range(6):
        _insert_decision(
            tenant_id=tenant_id,
            decision_id=f"dec-signal-{index}",
            policy_hash="policy-1",
            release_status="BLOCKED" if index < 4 else "ALLOWED",
            reason_code="RISK_SIGNAL_MISSING" if index < 4 else "APPROVED",
            created_at=now - timedelta(hours=index),
        )

    response = client.get(
        "/governance/recommendations",
        params={"tenant_id": tenant_id, "refresh": True, "lookback_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    recommendation_types = {item["recommendation_type"] for item in payload["recommendations"]}
    assert "MISSING_SIGNALS" in recommendation_types


def test_reco_ack_marks_resolved():
    _reset_db()
    tenant_id = "tenant-reco-ack"
    now = datetime.now(timezone.utc)
    for index in range(12):
        _insert_decision(
            tenant_id=tenant_id,
            decision_id=f"dec-ack-{index}",
            policy_hash="policy-ack",
            release_status="ALLOWED",
            reason_code="APPROVED",
            created_at=now - timedelta(hours=index),
        )
    for index in range(6):
        _insert_override(
            tenant_id=tenant_id,
            override_id=f"ovr-ack-{index}",
            decision_id=f"dec-ack-{index}",
            actor="alice",
            created_at=now - timedelta(hours=index),
        )

    generated = client.get(
        "/governance/recommendations",
        params={"tenant_id": tenant_id, "refresh": True},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert generated.status_code == 200, generated.text
    recommendations = generated.json()["recommendations"]
    assert recommendations
    recommendation_id = recommendations[0]["recommendation_id"]

    acknowledged = client.post(
        "/governance/recommendations/ack",
        json={"tenant_id": tenant_id, "recommendation_id": recommendation_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
    )
    assert acknowledged.status_code == 200, acknowledged.text
    ack_payload = acknowledged.json()
    assert ack_payload["ok"] is True
    assert ack_payload["recommendation"]["status"] in {"ACKED", "RESOLVED"}
