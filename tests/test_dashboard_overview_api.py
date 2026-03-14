from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.governance.dashboard_metrics import clear_active_strict_modes_cache, warm_dashboard_rollups_for_startup
from releasegate.server import _dashboard_json_response, app, clear_dashboard_overview_cache
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
    clear_active_strict_modes_cache()
    clear_dashboard_overview_cache()


def _insert_governance_rollup(
    *,
    tenant_id: str,
    date_utc: str,
    integrity_score: float,
    drift_index: float,
    override_rate: float,
    blocked_count: int,
    override_count: int = 2,
    decision_count: int = 10,
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
                1,
                int(override_count),
                int(decision_count),
                datetime.now(timezone.utc).isoformat(),
                details_json,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_blocked_decision(*, tenant_id: str, decision_id: str, created_at: datetime) -> None:
    payload = {
        "reason_code": "RISK_TOO_HIGH",
        "input_snapshot": {
            "request": {
                "issue_key": "RG-900",
                "transition_id": "31",
                "actor_account_id": "acct-dashboard",
                "environment": "prod",
                "project_key": "PROJ",
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
                "BLOCKED",
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


def _insert_active_strict_policy(*, tenant_id: str) -> None:
    policy_json = {"strict_fail_closed": True, "transition_rules": [{"transition_id": "31", "result": "BLOCK"}]}
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
                "policy-strict",
                "transition",
                "31",
                1,
                "ACTIVE",
                json.dumps(policy_json, separators=(",", ":"), sort_keys=True),
                "sha256:strict-policy",
                now,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _count_rollup_rows(*, tenant_id: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT COUNT(1) FROM governance_daily_metrics WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        return int(row[0] or 0) if row else 0
    finally:
        conn.close()


def _rollup_computed_at(*, tenant_id: str, date_utc: str) -> str:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            """
            SELECT computed_at
            FROM governance_daily_metrics
            WHERE tenant_id = ? AND date_utc = ?
            LIMIT 1
            """,
            (tenant_id, date_utc),
        ).fetchone()
        return str(row[0] or "") if row else ""
    finally:
        conn.close()


def _latest_security_audit(*, tenant_id: str, action: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            """
            SELECT action, metadata_json
            FROM security_audit_events
            WHERE tenant_id = ? AND action = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (tenant_id, action),
        ).fetchone()
        if not row:
            return {}
        metadata_raw = row[1] or "{}"
        try:
            metadata = json.loads(metadata_raw)
        except Exception:
            metadata = {}
        return {"action": row[0], "metadata": metadata}
    finally:
        conn.close()


def test_dashboard_overview_endpoint_returns_trends_and_blocked_items():
    _reset_db()
    tenant_id = "tenant-dashboard-overview"
    today = datetime.now(timezone.utc).date()
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=(today - timedelta(days=1)).isoformat(),
        integrity_score=93.5,
        drift_index=1.2,
        override_rate=0.08,
        blocked_count=2,
        override_count=8,
        decision_count=100,
        details_json=json.dumps(
            {
                "policy_drift": {
                    "signal_totals": {"WEAKEN_RISK_THRESHOLD": 2},
                    "recent_weakening_events": 1,
                }
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
    )
    _insert_governance_rollup(
        tenant_id=tenant_id,
        date_utc=today.isoformat(),
        integrity_score=92.0,
        drift_index=1.5,
        override_rate=0.09,
        blocked_count=3,
        override_count=9,
        decision_count=100,
        details_json=json.dumps(
            {
                "policy_drift": {
                    "signal_totals": {"WEAKEN_APPROVAL_REQUIREMENT": 3},
                    "recent_weakening_events": 2,
                }
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
    )
    _insert_blocked_decision(
        tenant_id=tenant_id,
        decision_id="dec-blocked-1",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    _insert_active_strict_policy(tenant_id=tenant_id)

    response = client.get(
        "/dashboard/overview",
        params={"tenant_id": tenant_id, "window_days": 30, "blocked_limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    envelope, body = _unwrap_dashboard_envelope(response)
    assert body["tenant_id"] == tenant_id
    assert body["trace_id"] == envelope["trace_id"]
    assert body["integrity_score"] == 92.0
    assert body["drift_index"] == 1.5
    assert body["override_rate"] == 0.09
    assert len(body["integrity_trend"]) == 2
    assert body["recent_blocked"][0]["decision_id"] == "dec-blocked-1"
    assert body["recent_blocked"][0]["subject_ref"] == "RG-900"
    assert body["recent_blocked"][0]["explainer_path"] == "/dashboard/decisions/dec-blocked-1/explainer"
    policy_strict = next(item for item in body["active_strict_modes"] if item["mode"] == "policy_strict_fail_closed")
    assert "reason" in policy_strict
    assert "last_changed_by" in policy_strict
    assert "last_changed_at" in policy_strict
    assert body["drift"]["current"] == 1.5
    assert body["drift"]["breakdown"]["signal_totals"] == {"WEAKEN_APPROVAL_REQUIREMENT": 3}
    assert response.headers.get("X-Request-Id") == envelope["trace_id"]
    assert response.headers.get("Cache-Control") == "private, max-age=30"

    integrity_response = client.get(
        "/dashboard/integrity",
        params={"tenant_id": tenant_id, "window_days": 30},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert integrity_response.status_code == 200, integrity_response.text
    integrity_envelope, integrity_body = _unwrap_dashboard_envelope(integrity_response)
    assert integrity_body["trace_id"] == integrity_envelope["trace_id"]
    assert integrity_response.headers.get("X-Request-Id") == integrity_envelope["trace_id"]
    assert integrity_response.headers.get("Cache-Control") == "private, max-age=60"
    trend = integrity_body["trend"]
    assert trend[-1]["override_count"] == 9
    assert trend[-1]["decision_count"] == 100
    assert trend[-1]["override_rate"] == 0.09


def test_dashboard_blocked_limit_validation():
    _reset_db()
    tenant_id = "tenant-dashboard-overview"
    response = client.get(
        "/dashboard/blocked",
        params={"tenant_id": tenant_id, "limit": 999},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 400
    body = response.json()
    assert body["generated_at"]
    assert body["trace_id"]
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["error_code"] == "VALIDATION_ERROR"


def test_non_dashboard_route_keeps_default_shape():
    _reset_db()
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert "generated_at" not in body
    assert "trace_id" not in body
    assert body["status"] == "ok"


def test_dashboard_overview_fallback_returns_null_drift_breakdown():
    _reset_db()
    tenant_id = "tenant-dashboard-overview-fallback"
    response = client.get(
        "/dashboard/overview",
        params={"tenant_id": tenant_id, "window_days": 30, "blocked_limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    _, body = _unwrap_dashboard_envelope(response)
    assert body["drift"]["current"] == 0.0
    assert _count_rollup_rows(tenant_id=tenant_id) == 1


def test_dashboard_blocked_cursor_pagination_returns_non_overlapping_pages():
    _reset_db()
    tenant_id = "tenant-dashboard-blocked-pagination"
    now = datetime.now(timezone.utc)
    for index in range(5):
        _insert_blocked_decision(
            tenant_id=tenant_id,
            decision_id=f"blocked-{index}",
            created_at=now - timedelta(minutes=index),
        )

    first = client.get(
        "/dashboard/blocked",
        params={"tenant_id": tenant_id, "limit": 2},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert first.status_code == 200, first.text
    first_envelope, first_body = _unwrap_dashboard_envelope(first)
    assert first_body["trace_id"] == first_envelope["trace_id"]
    assert first.headers.get("Cache-Control") == "private, max-age=10"
    assert len(first_body["items"]) == 2
    assert first_body["next_cursor"]

    second = client.get(
        "/dashboard/blocked",
        params={"tenant_id": tenant_id, "limit": 2, "cursor": first_body["next_cursor"]},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert second.status_code == 200, second.text
    _, second_body = _unwrap_dashboard_envelope(second)
    assert len(second_body["items"]) == 2

    first_ids = {item["decision_id"] for item in first_body["items"]}
    second_ids = {item["decision_id"] for item in second_body["items"]}
    assert first_ids.isdisjoint(second_ids)


def test_dashboard_overview_read_is_audited_with_trace_id():
    _reset_db()
    tenant_id = "tenant-dashboard-read-audit"
    response = client.get(
        "/dashboard/overview",
        params={"tenant_id": tenant_id, "window_days": 30, "blocked_limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    envelope, _ = _unwrap_dashboard_envelope(response)
    trace_id = envelope["trace_id"]
    audit = _latest_security_audit(tenant_id=tenant_id, action="DASHBOARD_READ_OVERVIEW")
    assert audit["action"] == "DASHBOARD_READ_OVERVIEW"
    assert audit["metadata"]["trace_id"] == trace_id


def test_dashboard_overview_allows_internal_service_auth(monkeypatch):
    _reset_db()
    tenant_id = "tenant-dashboard-internal"
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_KEY", "dashboard-internal-key")
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_SCOPES", "policy:read,enforcement:write")

    response = client.get(
        "/dashboard/overview",
        params={"tenant_id": tenant_id, "window_days": 30, "blocked_limit": 10},
        headers={
            "X-Internal-Service-Key": "dashboard-internal-key",
            "X-Tenant-Id": tenant_id,
        },
    )
    assert response.status_code == 200, response.text
    envelope, body = _unwrap_dashboard_envelope(response)
    assert body["tenant_id"] == tenant_id
    assert envelope["trace_id"] == body["trace_id"]


def test_dashboard_overview_debug_timing_is_exposed_for_internal_service(monkeypatch):
    _reset_db()
    tenant_id = "tenant-dashboard-debug-timing"
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_KEY", "dashboard-debug-key")
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_SCOPES", "policy:read,enforcement:write")

    response = client.get(
        "/dashboard/overview",
        params={
            "tenant_id": tenant_id,
            "window_days": 30,
            "blocked_limit": 10,
            "include_debug_timing": "true",
        },
        headers={
            "X-Internal-Service-Key": "dashboard-debug-key",
            "X-Tenant-Id": tenant_id,
        },
    )
    assert response.status_code == 200, response.text
    _, body = _unwrap_dashboard_envelope(response)
    assert isinstance(body["debug_timing_ms"], dict)
    assert body["debug_timing_ms"]["integrity_trend_load"] >= 0.0
    assert body["debug_timing_ms"]["recent_blocked_load"] >= 0.0
    assert body["debug_timing_ms"]["strict_modes_load"] >= 0.0
    assert body["debug_timing_ms"]["audit_dashboard_read"] >= 0.0
    assert body["debug_timing_ms"]["total_endpoint"] >= body["debug_timing_ms"]["total_service"]
    assert float(response.headers["X-Overview-Timing-Total-Ms"]) >= 0.0


def test_dashboard_overview_uses_short_ttl_payload_cache(monkeypatch):
    _reset_db()
    tenant_id = "tenant-dashboard-overview-cache"
    monkeypatch.setenv("RELEASEGATE_DASHBOARD_OVERVIEW_CACHE_TTL_SECONDS", "15")

    from releasegate import server as server_module
    from releasegate.governance import dashboard_metrics as metrics

    original_get_dashboard_overview = metrics.get_dashboard_overview
    calls = {"count": 0}
    monotonic_values = iter((100.0, 100.0, 110.0))

    def counting_get_dashboard_overview(**kwargs):
        calls["count"] += 1
        return original_get_dashboard_overview(**kwargs)

    monkeypatch.setattr(metrics, "get_dashboard_overview", counting_get_dashboard_overview)
    monkeypatch.setattr(server_module, "monotonic", lambda: next(monotonic_values))

    first = client.get(
        "/dashboard/overview",
        params={"tenant_id": tenant_id, "window_days": 30, "blocked_limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    second = client.get(
        "/dashboard/overview",
        params={"tenant_id": tenant_id, "window_days": 30, "blocked_limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert calls["count"] == 1


def test_dashboard_overview_debug_timing_bypasses_payload_cache(monkeypatch):
    _reset_db()
    tenant_id = "tenant-dashboard-overview-debug-bypass"
    monkeypatch.setenv("RELEASEGATE_DASHBOARD_OVERVIEW_CACHE_TTL_SECONDS", "15")
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_KEY", "dashboard-debug-cache-key")
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_SCOPES", "policy:read,enforcement:write")

    from releasegate.governance import dashboard_metrics as metrics

    original_get_dashboard_overview = metrics.get_dashboard_overview
    calls = {"count": 0}

    def counting_get_dashboard_overview(**kwargs):
        calls["count"] += 1
        return original_get_dashboard_overview(**kwargs)

    monkeypatch.setattr(metrics, "get_dashboard_overview", counting_get_dashboard_overview)

    first = client.get(
        "/dashboard/overview",
        params={
            "tenant_id": tenant_id,
            "window_days": 30,
            "blocked_limit": 10,
            "include_debug_timing": "true",
        },
        headers={
            "X-Internal-Service-Key": "dashboard-debug-cache-key",
            "X-Tenant-Id": tenant_id,
        },
    )
    second = client.get(
        "/dashboard/overview",
        params={
            "tenant_id": tenant_id,
            "window_days": 30,
            "blocked_limit": 10,
            "include_debug_timing": "true",
        },
        headers={
            "X-Internal-Service-Key": "dashboard-debug-cache-key",
            "X-Tenant-Id": tenant_id,
        },
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert calls["count"] == 2


def test_list_active_strict_modes_uses_short_ttl_cache(monkeypatch):
    _reset_db()
    tenant_id = "tenant-dashboard-strict-cache"
    _insert_active_strict_policy(tenant_id=tenant_id)
    monkeypatch.setenv("RELEASEGATE_ACTIVE_STRICT_MODES_CACHE_TTL_SECONDS", "30")

    from releasegate.governance import dashboard_metrics as metrics

    original_get_storage_backend = metrics.get_storage_backend
    original_monotonic = metrics.monotonic
    calls = {"fetchall": 0}

    class CountingStorage:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def fetchall(self, query, params=()):
            calls["fetchall"] += 1
            return self._wrapped.fetchall(query, params)

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

    wrapped_storage = CountingStorage(original_get_storage_backend())
    monotonic_values = iter((100.0, 100.0, 110.0, 145.0, 145.0))

    monkeypatch.setattr(metrics, "get_storage_backend", lambda: wrapped_storage)
    monkeypatch.setattr(metrics, "monotonic", lambda: next(monotonic_values))

    first = metrics.list_active_strict_modes(tenant_id=tenant_id)
    second = metrics.list_active_strict_modes(tenant_id=tenant_id)
    third = metrics.list_active_strict_modes(tenant_id=tenant_id)

    assert first
    assert second == first
    assert third == first
    assert calls["fetchall"] == 2


def test_dashboard_rollup_backfill_endpoint_is_idempotent():
    _reset_db()
    tenant_id = "tenant-dashboard-rollup"
    _insert_active_strict_policy(tenant_id=tenant_id)

    first = client.post(
        "/internal/dashboard/rollups/backfill",
        params={"tenant_id": tenant_id, "days": 3},
        headers=jwt_headers(
            tenant_id=tenant_id,
            roles=["admin"],
            scopes=["policy:write"],
        ),
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["ok"] is True
    assert first_body["days_written"] == 3
    assert _count_rollup_rows(tenant_id=tenant_id) == 3

    first_end_date = str(first_body["end_date_utc"])
    first_computed_at = _rollup_computed_at(tenant_id=tenant_id, date_utc=first_end_date)
    assert first_computed_at

    second = client.post(
        "/internal/dashboard/rollups/backfill",
        params={"tenant_id": tenant_id, "days": 3},
        headers=jwt_headers(
            tenant_id=tenant_id,
            roles=["admin"],
            scopes=["policy:write"],
        ),
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["ok"] is True
    assert second_body["days_written"] == 3
    assert _count_rollup_rows(tenant_id=tenant_id) == 3

    second_computed_at = _rollup_computed_at(tenant_id=tenant_id, date_utc=first_end_date)
    assert second_computed_at
    assert second_computed_at >= first_computed_at


def test_dashboard_rollup_backfill_requires_admin():
    _reset_db()
    tenant_id = "tenant-dashboard-rollup-auth"
    response = client.post(
        "/internal/dashboard/rollups/backfill",
        params={"tenant_id": tenant_id, "days": 2},
        headers=jwt_headers(
            tenant_id=tenant_id,
            roles=["auditor"],
            scopes=["policy:read"],
        ),
    )
    assert response.status_code == 403


def test_dashboard_rollup_startup_warmup_seeds_known_tenants():
    _reset_db()
    tenant_id = "tenant-dashboard-startup-warm"
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO tenant_onboarding_config (
                tenant_id, jira_instance_id, project_keys_json, workflow_ids_json,
                transition_ids_json, mode, canary_pct, created_at, updated_at
            ) VALUES (?, ?, '[]', '[]', '[]', 'simulation', 0, ?, ?)
            """,
            (
                tenant_id,
                "https://example.atlassian.net",
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    report = warm_dashboard_rollups_for_startup(limit=10)
    assert report["tenants_warmed"] >= 1
    assert tenant_id in report["warmed_tenants"]
    assert _count_rollup_rows(tenant_id=tenant_id) == 1


def test_internal_slo_endpoint_reports_latency_and_error_rate(monkeypatch):
    _reset_db()
    tenant_id = "tenant-dashboard-slo"

    ok_response = client.get(
        "/dashboard/overview",
        params={"tenant_id": tenant_id, "window_days": 30, "blocked_limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert ok_response.status_code == 200, ok_response.text

    unauthorized = client.get("/dashboard/overview", params={"tenant_id": tenant_id, "window_days": 30, "blocked_limit": 10})
    assert unauthorized.status_code == 401

    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_KEY", "dashboard-slo-key")
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_SCOPES", "policy:read")

    slo = client.get(
        "/internal/slo",
        headers={
            "X-Internal-Service-Key": "dashboard-slo-key",
            "X-Tenant-Id": tenant_id,
        },
    )
    assert slo.status_code == 200, slo.text
    payload = slo.json()
    assert payload["http_requests_total"] >= 2
    assert payload["http_errors_4xx5xx_total"] >= 1
    assert payload["latency_ms_p95"] >= 0.0
    assert payload["routes"]["/dashboard/overview"]["http_requests_total"] >= 2
    assert payload["routes"]["/dashboard/overview"]["http_errors_4xx5xx_total"] >= 1
    assert payload["routes"]["/dashboard/overview"]["latency_ms_p95"] >= 0.0
    assert payload["targets"]["p95_latency_ms"] == 500.0
    assert payload["targets"]["error_rate_5xx"] == 0.001


def test_prometheus_metrics_exports_slo_gauges():
    _reset_db()
    metrics = client.get("/metrics")
    assert metrics.status_code == 200, metrics.text
    body = metrics.text
    assert "releasegate_http_requests_total " in body
    assert "releasegate_http_errors_5xx_total " in body
    assert "releasegate_http_error_rate_5xx_ratio " in body
    assert "releasegate_http_latency_ms_p95 " in body


def test_dashboard_json_response_encodes_datetimes():
    response = _dashboard_json_response(
        trace_id="trace-dashboard-json",
        cache_control="private, max-age=30",
        payload={
            "tenant_id": "tenant-dashboard-json",
            "updated_at": datetime(2026, 3, 7, 4, 0, tzinfo=timezone.utc),
        },
    )
    assert response.status_code == 200
    assert b"2026-03-07T04:00:00+00:00" in response.body
