from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.server import app, clear_dashboard_alerts_cache
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
    clear_dashboard_alerts_cache()


def _insert_governance_rollup(
    *,
    tenant_id: str,
    date_utc: str,
    integrity_score: float,
    drift_index: float,
    override_rate: float,
    blocked_count: int,
    strict_mode_count: int,
    override_count: int,
    decision_count: int,
    details_json: str = "{}",
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
                float(override_rate),
                int(blocked_count),
                int(strict_mode_count),
                int(override_count),
                int(decision_count),
                datetime.now(timezone.utc).isoformat(),
                details_json,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_dashboard_alerts_emits_override_spike_from_rollup_history():
    _reset_db()
    tenant_id = "tenant-dashboard-alerts-spike"
    today = datetime.now(timezone.utc).date()
    for offset in range(7):
        day = (today - timedelta(days=7 - offset)).isoformat()
        _insert_governance_rollup(
            tenant_id=tenant_id,
            date_utc=day,
            integrity_score=95.0,
            drift_index=0.01,
            override_rate=0.02,
            blocked_count=1,
            strict_mode_count=3,
            override_count=2,
            decision_count=100,
        )
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=today.isoformat(),
        integrity_score=92.0,
        drift_index=0.01,
        override_rate=0.10,
        blocked_count=4,
        strict_mode_count=3,
        override_count=10,
        decision_count=100,
        details_json=json.dumps(
            {"override_abuse_index": 0.18},
            separators=(",", ":"),
            sort_keys=True,
        ),
    )

    response = client.get(
        "/dashboard/alerts",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    envelope, body = _unwrap_dashboard_envelope(response)
    assert body["trace_id"] == envelope["trace_id"]
    assert response.headers.get("X-Request-Id") == envelope["trace_id"]
    assert response.headers.get("Cache-Control") == "private, max-age=60"
    assert body["window_days"] == 30
    alert = next(item for item in body["alerts"] if item["code"] == "OVERRIDE_SPIKE")
    assert alert["severity"] == "high"
    assert alert["date_utc"] == today.isoformat()
    assert alert["details"]["baseline_7d"] == 0.02
    assert alert["details"]["today"] == 0.1
    assert body["current_override_abuse_index"] == 0.18


def test_dashboard_alerts_emits_strict_mode_drop():
    _reset_db()
    tenant_id = "tenant-dashboard-alerts-strict-drop"
    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=yesterday.isoformat(),
        integrity_score=96.0,
        drift_index=0.01,
        override_rate=0.01,
        blocked_count=0,
        strict_mode_count=3,
        override_count=1,
        decision_count=100,
    )
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=today.isoformat(),
        integrity_score=95.5,
        drift_index=0.01,
        override_rate=0.01,
        blocked_count=0,
        strict_mode_count=1,
        override_count=1,
        decision_count=100,
    )

    response = client.get(
        "/dashboard/alerts",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    envelope, body = _unwrap_dashboard_envelope(response)
    assert body["trace_id"] == envelope["trace_id"]
    assert response.headers.get("X-Request-Id") == envelope["trace_id"]
    assert response.headers.get("Cache-Control") == "private, max-age=60"
    alerts = body["alerts"]
    strict_drop = next(item for item in alerts if item["code"] == "STRICT_MODE_DROP")
    assert strict_drop["severity"] == "high"
    assert strict_drop["details"]["today"] == 1
    assert strict_drop["details"]["yesterday"] == 3


def test_dashboard_alerts_uses_short_ttl_cache(monkeypatch):
    _reset_db()
    tenant_id = "tenant-dashboard-alerts-cache"
    today = datetime.now(timezone.utc).date()
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=today.isoformat(),
        integrity_score=94.0,
        drift_index=0.01,
        override_rate=0.02,
        blocked_count=1,
        strict_mode_count=2,
        override_count=2,
        decision_count=100,
    )

    from releasegate.governance import dashboard_metrics as metrics

    call_count = {"value": 0}
    original_list_dashboard_alerts = metrics.list_dashboard_alerts

    def counting_list_dashboard_alerts(**kwargs):
        call_count["value"] += 1
        return original_list_dashboard_alerts(**kwargs)

    monkeypatch.setattr(metrics, "list_dashboard_alerts", counting_list_dashboard_alerts)

    first = client.get(
        "/dashboard/alerts",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    second = client.get(
        "/dashboard/alerts",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert call_count["value"] == 1
