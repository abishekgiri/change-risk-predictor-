from __future__ import annotations

import os
import sqlite3

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.integrations.jira import routes as jira_routes
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


def test_onboarding_status_defaults_to_simulation_when_config_missing():
    _reset_db()
    tenant_id = "tenant-onboarding-default"

    response = client.get(
        "/onboarding/status",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(
            tenant_id=tenant_id,
            scopes=["policy:read"],
        ),
    )

    assert response.status_code == 200
    payload = _unwrap_envelope(response)
    assert payload["tenant_id"] == tenant_id
    assert payload["onboarding_completed"] is False
    assert payload["config"]["mode"] == "simulation"
    assert payload["config"]["project_keys"] == []
    assert payload["config"]["workflow_ids"] == []
    assert payload["config"]["transition_ids"] == []


def test_onboarding_setup_persists_config_and_status_returns_saved_values():
    _reset_db()
    tenant_id = "tenant-onboarding-save"

    setup_response = client.post(
        "/onboarding/setup",
        headers=jwt_headers(
            tenant_id=tenant_id,
            scopes=["policy:write"],
        ),
        json={
            "tenant_id": tenant_id,
            "jira_instance_id": "https://jira.example.com",
            "project_keys": ["PAYMENTS", "BACKEND"],
            "workflow_ids": ["wf-release", "wf-default"],
            "transition_ids": ["31", "45"],
            "mode": "canary",
            "canary_pct": 20,
        },
    )
    assert setup_response.status_code == 200
    setup_payload = _unwrap_envelope(setup_response)
    assert setup_payload["onboarding_completed"] is True
    assert setup_payload["config"]["jira_instance_id"] == "https://jira.example.com"
    assert setup_payload["config"]["mode"] == "canary"
    assert setup_payload["config"]["canary_pct"] == 20
    assert setup_payload["config"]["project_keys"] == ["PAYMENTS", "BACKEND"]

    status_response = client.get(
        "/onboarding/status",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(
            tenant_id=tenant_id,
            scopes=["policy:read"],
        ),
    )
    assert status_response.status_code == 200
    status_payload = _unwrap_envelope(status_response)
    assert status_payload["onboarding_completed"] is True
    assert status_payload["config"]["workflow_ids"] == ["wf-release", "wf-default"]
    assert status_payload["config"]["transition_ids"] == ["31", "45"]


def test_onboarding_status_is_tenant_scoped():
    _reset_db()
    tenant_a = "tenant-onboarding-a"
    tenant_b = "tenant-onboarding-b"

    setup_response = client.post(
        "/onboarding/setup",
        headers=jwt_headers(
            tenant_id=tenant_a,
            scopes=["policy:write"],
        ),
        json={
            "tenant_id": tenant_a,
            "project_keys": ["PAYMENTS"],
            "workflow_ids": ["wf-release"],
            "transition_ids": ["31"],
            "mode": "strict",
        },
    )
    assert setup_response.status_code == 200

    status_other_tenant = client.get(
        "/onboarding/status",
        params={"tenant_id": tenant_b},
        headers=jwt_headers(
            tenant_id=tenant_b,
            scopes=["policy:read"],
        ),
    )
    assert status_other_tenant.status_code == 200
    status_payload = _unwrap_envelope(status_other_tenant)
    assert status_payload["tenant_id"] == tenant_b
    assert status_payload["onboarding_completed"] is False


def test_onboarding_setup_requires_admin_or_operator_role():
    _reset_db()
    tenant_id = "tenant-onboarding-scope"

    response = client.post(
        "/onboarding/setup",
        headers=jwt_headers(
            tenant_id=tenant_id,
            roles=["auditor"],
            scopes=["policy:write"],
        ),
        json={
            "tenant_id": tenant_id,
            "project_keys": ["PAYMENTS"],
            "workflow_ids": ["wf-release"],
            "transition_ids": ["31"],
            "mode": "simulation",
        },
    )
    assert response.status_code == 403


def test_onboarding_setup_records_connect_and_scope_metrics_once():
    _reset_db()
    tenant_id = "tenant-onboarding-metrics"

    first = client.post(
        "/onboarding/setup",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={
            "tenant_id": tenant_id,
            "jira_instance_id": "https://jira.example.com",
            "project_keys": ["PAYMENTS"],
            "workflow_ids": ["wf-release"],
            "transition_ids": ["31"],
            "mode": "simulation",
        },
    )
    assert first.status_code == 200, first.text
    assert _metric_event_count(tenant_id=tenant_id, metric_name="onboarding_jira_connected") == 1
    assert _metric_event_count(tenant_id=tenant_id, metric_name="onboarding_transition_scope_ready") == 1

    second = client.post(
        "/onboarding/setup",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"]),
        json={
            "tenant_id": tenant_id,
            "jira_instance_id": "https://jira.example.com",
            "project_keys": ["PAYMENTS"],
            "workflow_ids": ["wf-release"],
            "transition_ids": ["31"],
            "mode": "simulation",
        },
    )
    assert second.status_code == 200, second.text
    assert _metric_event_count(tenant_id=tenant_id, metric_name="onboarding_jira_connected") == 1
    assert _metric_event_count(tenant_id=tenant_id, metric_name="onboarding_transition_scope_ready") == 1


def test_onboarding_telemetry_records_snapshot_shown_event():
    _reset_db()
    tenant_id = "tenant-onboarding-telemetry"

    response = client.post(
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
    assert response.status_code == 200, response.text
    payload = _unwrap_envelope(response)
    assert payload["status"] == "recorded"
    assert payload["event_name"] == "snapshot_shown"
    assert payload["recorded_at"]
    assert _metric_event_count(tenant_id=tenant_id, metric_name="onboarding_snapshot_shown") == 1


def test_jira_discovery_endpoints_return_expected_shapes(monkeypatch):
    _reset_db()
    tenant_id = "tenant-jira-discovery"

    monkeypatch.setattr(
        jira_routes,
        "discover_jira_projects",
        lambda: {
            "source": "jira",
            "items": [{"project_key": "PAYMENTS", "name": "Payments", "project_id": "10001"}],
        },
    )
    monkeypatch.setattr(
        jira_routes,
        "discover_jira_workflows",
        lambda project_key=None: {
            "source": "jira",
            "items": [
                {"workflow_id": "wf-release", "workflow_name": "Release Workflow", "project_keys": [project_key or "PAYMENTS"]}
            ],
        },
    )
    monkeypatch.setattr(
        jira_routes,
        "discover_jira_workflow_transitions",
        lambda workflow_id, project_key=None: {
            "source": "jira",
            "items": [
                {
                    "transition_id": "31",
                    "transition_name": "Done",
                    "workflow_id": workflow_id,
                    "workflow_name": "Release Workflow",
                    "project_keys": [project_key or "PAYMENTS"],
                }
            ],
        },
    )

    projects_response = client.get(
        "/integrations/jira/projects",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert projects_response.status_code == 200
    projects_payload = projects_response.json()
    assert projects_payload["tenant_id"] == tenant_id
    assert projects_payload["source"] == "jira"
    assert projects_payload["items"][0]["project_key"] == "PAYMENTS"

    workflows_response = client.get(
        "/integrations/jira/workflows",
        params={"tenant_id": tenant_id, "project_key": "PAYMENTS"},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert workflows_response.status_code == 200
    workflows_payload = workflows_response.json()
    assert workflows_payload["project_key"] == "PAYMENTS"
    assert workflows_payload["items"][0]["workflow_id"] == "wf-release"

    transitions_response = client.get(
        "/integrations/jira/workflows/wf-release/transitions",
        params={"tenant_id": tenant_id, "project_key": "PAYMENTS"},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert transitions_response.status_code == 200
    transitions_payload = transitions_response.json()
    assert transitions_payload["workflow_id"] == "wf-release"
    assert transitions_payload["items"][0]["transition_id"] == "31"


def test_jira_discovery_requires_supported_role():
    _reset_db()
    tenant_id = "tenant-jira-scope"
    response = client.get(
        "/integrations/jira/projects",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(
            tenant_id=tenant_id,
            roles=["guest"],
            scopes=["policy:read"],
        ),
    )
    assert response.status_code == 403
