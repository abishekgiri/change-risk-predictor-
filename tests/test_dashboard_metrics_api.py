from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.server import app, clear_dashboard_metrics_timeseries_cache
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
    clear_dashboard_metrics_timeseries_cache()


def _insert_governance_rollup(
    *,
    tenant_id: str,
    date_utc: str,
    integrity_score: float,
    drift_index: float,
    override_count: int,
    decision_count: int,
    blocked_count: int,
) -> None:
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
                float(integrity_score),
                float(drift_index),
                float(override_count / decision_count if decision_count else 0.0),
                int(blocked_count),
                1,
                int(override_count),
                int(decision_count),
                datetime.now(timezone.utc).isoformat(),
                "{}",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_decision(
    *,
    tenant_id: str,
    decision_id: str,
    created_at: datetime,
    release_status: str,
    reason_code: str = "RISK_TOO_HIGH",
) -> None:
    payload = {
        "reason_code": reason_code,
        "input_snapshot": {
            "request": {
                "issue_key": f"RG-{decision_id}",
                "transition_id": "31",
                "actor_account_id": "acct-observability",
                "environment": "prod",
                "project_key": "PAYMENTS",
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


def _insert_override(*, tenant_id: str, override_id: str, decision_id: str, created_at: datetime) -> None:
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
                "RG-101",
                decision_id,
                "acct-observability",
                "Emergency override",
                "transition",
                "31",
                f"idem-{override_id}",
                "prev-hash",
                f"event-hash-{override_id}",
                3600,
                (created_at + timedelta(hours=1)).isoformat(),
                "acct-observability",
                "acct-admin",
                created_at.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_dashboard_metrics_timeseries_and_summary():
    _reset_db()
    tenant_id = "tenant-dashboard-metrics-ts"
    today = datetime.now(timezone.utc).date()
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=(today - timedelta(days=1)).isoformat(),
        integrity_score=95.0,
        drift_index=0.02,
        override_count=2,
        decision_count=40,
        blocked_count=3,
    )
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=today.isoformat(),
        integrity_score=93.0,
        drift_index=0.05,
        override_count=5,
        decision_count=50,
        blocked_count=6,
    )

    response = client.get(
        "/dashboard/metrics/timeseries",
        params={"tenant_id": tenant_id, "metric": "override_rate", "window_days": 30, "bucket": "day"},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    envelope, payload = _unwrap_dashboard_envelope(response)
    assert payload["trace_id"] == envelope["trace_id"]
    assert payload["metric"] == "override_rate"
    assert payload["bucket"] == "day"
    assert len(payload["series"]) == 2
    assert payload["series"][-1]["value"] == 0.1
    assert payload["series"][-1]["numerator"] == 5
    assert payload["series"][-1]["denominator"] == 50

    summary_response = client.get(
        "/dashboard/metrics/summary",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert summary_response.status_code == 200, summary_response.text
    summary_envelope, summary_payload = _unwrap_dashboard_envelope(summary_response)
    assert summary_payload["trace_id"] == summary_envelope["trace_id"]
    assert summary_payload["metrics"]["integrity_score"]["value"] == 93.0
    assert summary_payload["metrics"]["override_rate"]["value"] == 0.1
    assert summary_payload["metrics"]["override_rate"]["previous"] == 0.05
    assert summary_payload["metrics"]["override_rate"]["delta"] == 0.05


def test_dashboard_metrics_drilldown_returns_metric_specific_decisions():
    _reset_db()
    tenant_id = "tenant-dashboard-metrics-drilldown"
    now = datetime.now(timezone.utc)

    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-blocked-1",
        created_at=now - timedelta(hours=3),
        release_status="BLOCKED",
        reason_code="POLICY_BLOCKED",
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id="dec-allowed-1",
        created_at=now - timedelta(hours=2),
        release_status="ALLOWED",
        reason_code="APPROVED",
    )
    _insert_override(
        tenant_id=tenant_id,
        override_id="ovr-1",
        decision_id="dec-allowed-1",
        created_at=now - timedelta(hours=1),
    )

    override_response = client.get(
        "/dashboard/metrics/drilldown",
        params={"tenant_id": tenant_id, "metric": "override_rate", "window_days": 30, "limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert override_response.status_code == 200, override_response.text
    _, override_payload = _unwrap_dashboard_envelope(override_response)
    assert override_payload["metric"] == "override_rate"
    decision_ids = [item["decision_id"] for item in override_payload["items"]]
    assert "dec-allowed-1" in decision_ids

    blocked_response = client.get(
        "/dashboard/metrics/drilldown",
        params={"tenant_id": tenant_id, "metric": "block_frequency", "window_days": 30, "limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert blocked_response.status_code == 200, blocked_response.text
    _, blocked_payload = _unwrap_dashboard_envelope(blocked_response)
    assert blocked_payload["metric"] == "block_frequency"
    assert all(item["decision_status"] in {"BLOCKED", "ERROR", "DENIED"} for item in blocked_payload["items"])


def test_dashboard_metrics_timeseries_rejects_unknown_metric():
    _reset_db()
    tenant_id = "tenant-dashboard-metrics-invalid"
    response = client.get(
        "/dashboard/metrics/timeseries",
        params={"tenant_id": tenant_id, "metric": "unknown"},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 400


def test_dashboard_metrics_timeseries_uses_short_ttl_cache(monkeypatch):
    _reset_db()
    tenant_id = "tenant-dashboard-metrics-cache"
    today = datetime.now(timezone.utc).date()
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=today.isoformat(),
        integrity_score=93.0,
        drift_index=0.05,
        override_count=5,
        decision_count=50,
        blocked_count=6,
    )
    monkeypatch.setenv("RELEASEGATE_DASHBOARD_METRICS_TIMESERIES_CACHE_TTL_SECONDS", "30")

    from releasegate import server as server_module
    from releasegate.governance import dashboard_metrics as metrics

    original_get_metrics_timeseries = metrics.get_metrics_timeseries
    calls = {"count": 0}
    monotonic_values = iter((100.0, 100.0, 110.0))

    def counting_get_metrics_timeseries(**kwargs):
        calls["count"] += 1
        return original_get_metrics_timeseries(**kwargs)

    monkeypatch.setattr(metrics, "get_metrics_timeseries", counting_get_metrics_timeseries)
    monkeypatch.setattr(server_module, "monotonic", lambda: next(monotonic_values))

    first = client.get(
        "/dashboard/metrics/timeseries",
        params={"tenant_id": tenant_id, "metric": "override_rate", "window_days": 30, "bucket": "day"},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    second = client.get(
        "/dashboard/metrics/timeseries",
        params={"tenant_id": tenant_id, "metric": "override_rate", "window_days": 30, "bucket": "day"},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert calls["count"] == 1
