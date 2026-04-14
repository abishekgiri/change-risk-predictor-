from __future__ import annotations

import json
import os
import sqlite3

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


def _unwrap_envelope(response) -> dict:
    body = response.json()
    assert body.get("generated_at")
    assert body.get("trace_id")
    assert isinstance(body.get("data"), dict)
    return body["data"]


def _metric_event_count(*, tenant_id: str, metric_name: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT COUNT(1) FROM metrics_events WHERE tenant_id = ? AND metric_name = ?",
            (tenant_id, metric_name),
        ).fetchone()
        return int(row[0] or 0) if row else 0
    finally:
        conn.close()


def _latest_metric_event(*, tenant_id: str, metric_name: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            """
            SELECT metric_value, created_at, metadata_json
            FROM metrics_events
            WHERE tenant_id = ? AND metric_name = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (tenant_id, metric_name),
        ).fetchone()
        if not row:
            return None
        metadata = json.loads(row[2] or "{}")
        return {
            "metric_value": int(row[0] or 0),
            "created_at": row[1],
            "metadata": metadata if isinstance(metadata, dict) else {},
        }
    finally:
        conn.close()


def _configure_onboarding(tenant_id: str, transition_ids: list[str] | None = None) -> None:
    resolved_transition_ids = ["31"] if transition_ids is None else transition_ids
    response = client.post(
        "/onboarding/setup",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={
            "tenant_id": tenant_id,
            "jira_instance_id": "https://jira.example.com",
            "project_keys": ["PAYMENTS"],
            "workflow_ids": ["wf-release"],
            "transition_ids": resolved_transition_ids,
            "mode": "simulation",
        },
    )
    assert response.status_code == 200, response.text


def test_onboarding_activation_defaults_to_simulation_when_missing():
    _reset_db()
    tenant_id = "tenant-activation-default"

    response = client.get(
        "/onboarding/activation",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )

    assert response.status_code == 200
    payload = _unwrap_envelope(response)
    assert payload["tenant_id"] == tenant_id
    assert payload["mode"] == "simulation"
    assert payload["canary_pct"] is None
    assert payload["applied"] is False


def test_onboarding_activation_canary_requires_percentage_and_persists():
    _reset_db()
    tenant_id = "tenant-activation-canary"
    _configure_onboarding(tenant_id)

    missing_pct = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary"},
    )
    assert missing_pct.status_code == 400
    assert "canary_pct is required" in str(missing_pct.json())

    invalid_pct = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 101},
    )
    assert invalid_pct.status_code == 400
    assert "canary_pct must be between 1 and 100" in str(invalid_pct.json())

    apply_response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 15},
    )
    assert apply_response.status_code == 200
    apply_payload = _unwrap_envelope(apply_response)
    assert apply_payload["mode"] == "canary"
    assert apply_payload["canary_pct"] == 15
    assert apply_payload["applied"] is True
    assert apply_payload["updated_at"]

    get_response = client.get(
        "/onboarding/activation",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert get_response.status_code == 200
    get_payload = _unwrap_envelope(get_response)
    assert get_payload["mode"] == "canary"
    assert get_payload["canary_pct"] == 15
    assert get_payload["applied"] is True


def test_onboarding_activation_strict_clears_canary_percentage():
    _reset_db()
    tenant_id = "tenant-activation-strict"
    _configure_onboarding(tenant_id)

    canary_response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 20},
    )
    assert canary_response.status_code == 200

    strict_response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "strict", "canary_pct": 20},
    )
    assert strict_response.status_code == 200
    strict_payload = _unwrap_envelope(strict_response)
    assert strict_payload["mode"] == "strict"
    assert strict_payload["canary_pct"] is None
    assert strict_payload["applied"] is True


def test_onboarding_activation_is_tenant_scoped():
    _reset_db()
    tenant_a = "tenant-activation-a"
    tenant_b = "tenant-activation-b"
    _configure_onboarding(tenant_a)

    apply_response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_a, scopes=["policy:write"]),
        json={"tenant_id": tenant_a, "mode": "strict"},
    )
    assert apply_response.status_code == 200

    other_response = client.get(
        "/onboarding/activation",
        params={"tenant_id": tenant_b},
        headers=jwt_headers(tenant_id=tenant_b, scopes=["policy:read"]),
    )
    assert other_response.status_code == 200
    payload = _unwrap_envelope(other_response)
    assert payload["tenant_id"] == tenant_b
    assert payload["mode"] == "simulation"
    assert payload["applied"] is False


def test_onboarding_activation_requires_admin_or_operator_role():
    _reset_db()
    tenant_id = "tenant-activation-role"

    response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(
            tenant_id=tenant_id,
            roles=["auditor"],
            scopes=["policy:write"],
        ),
        json={"tenant_id": tenant_id, "mode": "strict"},
    )
    assert response.status_code == 403


def test_onboarding_activation_rollback_reverts_to_previous_state():
    _reset_db()
    tenant_id = "tenant-activation-rollback"
    _configure_onboarding(tenant_id)

    observe = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "simulation"},
    )
    assert observe.status_code == 200

    canary = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 15},
    )
    assert canary.status_code == 200

    strict = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "strict"},
    )
    assert strict.status_code == 200

    rollback_to_canary = client.post(
        "/onboarding/activation/rollback",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id},
    )
    assert rollback_to_canary.status_code == 200
    rollback_payload = _unwrap_envelope(rollback_to_canary)
    assert rollback_payload["status"] == "rolled_back"
    assert rollback_payload["activation"]["mode"] == "canary"
    assert rollback_payload["activation"]["canary_pct"] == 15

    rollback_to_simulation = client.post(
        "/onboarding/activation/rollback",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id},
    )
    assert rollback_to_simulation.status_code == 200
    rollback_payload = _unwrap_envelope(rollback_to_simulation)
    assert rollback_payload["activation"]["mode"] == "simulation"
    assert rollback_payload["activation"]["canary_pct"] is None


def test_onboarding_activation_rollback_requires_previous_state():
    _reset_db()
    tenant_id = "tenant-activation-rollback-empty"

    response = client.post(
        "/onboarding/activation/rollback",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id},
    )
    assert response.status_code == 400
    assert "No previous activation state" in str(response.json())


def test_onboarding_activation_rollback_works_after_first_change_from_implicit_default():
    _reset_db()
    tenant_id = "tenant-activation-first-change"
    _configure_onboarding(tenant_id)

    apply_response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 25},
    )
    assert apply_response.status_code == 200

    rollback_response = client.post(
        "/onboarding/activation/rollback",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id},
    )
    assert rollback_response.status_code == 200
    rollback_payload = _unwrap_envelope(rollback_response)
    assert rollback_payload["status"] == "rolled_back"
    assert rollback_payload["activation"]["mode"] == "simulation"
    assert rollback_payload["activation"]["canary_pct"] is None


def test_onboarding_activation_history_endpoint_returns_recent_entries():
    _reset_db()
    tenant_id = "tenant-activation-history"
    _configure_onboarding(tenant_id)

    canary = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 20},
    )
    assert canary.status_code == 200

    strict = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "strict"},
    )
    assert strict.status_code == 200

    response = client.get(
        "/onboarding/activation/history",
        params={"tenant_id": tenant_id, "limit": 10},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200
    payload = _unwrap_envelope(response)
    assert payload["tenant_id"] == tenant_id
    assert payload["limit"] == 10
    assert payload["current"]["mode"] == "strict"
    assert len(payload["items"]) >= 2
    assert payload["items"][0]["mode"] == "canary"
    assert payload["items"][1]["mode"] == "simulation"


def test_onboarding_activation_rollback_requires_admin_or_operator_role():
    _reset_db()
    tenant_id = "tenant-activation-rollback-role"

    response = client.post(
        "/onboarding/activation/rollback",
        headers=jwt_headers(
            tenant_id=tenant_id,
            roles=["auditor"],
            scopes=["policy:write"],
        ),
        json={"tenant_id": tenant_id},
    )
    assert response.status_code == 403


def test_onboarding_activation_blocks_canary_and_strict_when_no_transitions_are_configured():
    _reset_db()
    tenant_id = "tenant-activation-no-transitions"
    _configure_onboarding(tenant_id, transition_ids=[])

    canary_response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 10},
    )
    assert canary_response.status_code == 400
    assert "Select at least one protected transition" in str(canary_response.json())

    strict_response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "strict"},
    )
    assert strict_response.status_code == 400
    assert "Select at least one protected transition" in str(strict_response.json())
    assert _metric_event_count(
        tenant_id=tenant_id,
        metric_name="onboarding_zero_transition_guard_triggered",
    ) == 2


def test_onboarding_activation_records_canary_metrics():
    _reset_db()
    tenant_id = "tenant-activation-metrics"
    _configure_onboarding(tenant_id)

    response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 10},
    )
    assert response.status_code == 200, response.text
    assert _metric_event_count(tenant_id=tenant_id, metric_name="onboarding_canary_enabled") == 1
    assert _metric_event_count(tenant_id=tenant_id, metric_name="onboarding_time_to_canary_seconds") == 1


def test_onboarding_activation_records_snapshot_hesitation_metric_when_snapshot_was_shown():
    _reset_db()
    tenant_id = "tenant-activation-hesitation"
    _configure_onboarding(tenant_id)

    telemetry_response = client.post(
        "/onboarding/telemetry",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
        json={
            "tenant_id": tenant_id,
            "event_name": "snapshot_shown",
            "metadata": {
                "snapshot_ran_at": "2026-04-13T12:00:00+00:00",
                "total_transitions": 87,
                "starter_pack": "conservative",
            },
        },
    )
    assert telemetry_response.status_code == 200, telemetry_response.text

    activation_response = client.post(
        "/onboarding/activation",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={"tenant_id": tenant_id, "mode": "canary", "canary_pct": 10},
    )
    assert activation_response.status_code == 200, activation_response.text

    hesitation_event = _latest_metric_event(
        tenant_id=tenant_id,
        metric_name="onboarding_snapshot_hesitation_seconds",
    )
    assert hesitation_event is not None
    assert hesitation_event["metric_value"] >= 0
    assert hesitation_event["metadata"]["starter_pack"] == "conservative"
    assert hesitation_event["metadata"]["total_transitions"] == 87
