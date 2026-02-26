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


def _table_count(table_name: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def test_policy_registry_api_create_activate_and_list():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api")

    create_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "2",
            "status": "DRAFT",
            "policy_json": {
                "strict_fail_closed": True,
                "required_transitions": ["2"],
                "transition_rules": [{"transition_id": "2", "result": "ALLOW"}],
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    created = create_resp.json()
    assert created["status"] == "DRAFT"
    assert created["lint_errors"] == []

    activate_resp = client.post(
        f"/policies/{created['policy_id']}/activate",
        headers=headers,
        json={"tenant_id": "tenant-registry-api"},
    )
    assert activate_resp.status_code == 200, activate_resp.text
    activated = activate_resp.json()
    assert activated["status"] == "ACTIVE"

    list_resp = client.get(
        "/policies",
        headers=headers,
        params={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "2",
            "status": "ACTIVE",
        },
    )
    assert list_resp.status_code == 200
    payload = list_resp.json()
    assert payload["tenant_id"] == "tenant-registry-api"
    assert len(payload["policies"]) == 1
    assert payload["policies"][0]["policy_id"] == created["policy_id"]


def test_policy_registry_api_rejects_cross_tenant_access_by_default():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api-a")
    response = client.get(
        "/policies",
        headers=headers,
        params={
            "tenant_id": "tenant-registry-api-b",
            "scope_type": "transition",
            "scope_id": "2",
        },
    )
    assert response.status_code == 403
    detail = response.json().get("detail") or {}
    assert detail.get("error_code") == "TENANT_SCOPE_FORBIDDEN"


def test_policy_registry_api_allows_cross_tenant_for_platform_admin_when_enabled(monkeypatch):
    _reset_db()
    monkeypatch.setenv("RELEASEGATE_ALLOW_CROSS_TENANT_ACCESS", "true")
    headers = jwt_headers(
        tenant_id="tenant-registry-api-a",
        roles=["admin", "platform_admin"],
        scopes=["policy:read", "tenant:impersonate"],
    )
    response = client.get(
        "/policies",
        headers=headers,
        params={
            "tenant_id": "tenant-registry-api-b",
            "scope_type": "transition",
            "scope_id": "2",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["tenant_id"] == "tenant-registry-api-b"


def test_policy_registry_api_simulate_decision_uses_effective_policy():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api")

    # Org base
    org_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "org",
            "scope_id": "tenant-registry-api",
            "status": "ACTIVE",
            "policy_json": {
                "strict_fail_closed": True,
                "transition_rules": [{"transition_id": "31", "result": "ALLOW", "priority": 200}],
            },
        },
    )
    assert org_resp.status_code == 200, org_resp.text

    # Transition override
    transition_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "31",
            "status": "ACTIVE",
            "policy_json": {
                "transition_rules": [{"transition_id": "31", "result": "BLOCK", "priority": 100}],
            },
        },
    )
    assert transition_resp.status_code == 200, transition_resp.text

    simulate_resp = client.post(
        "/simulate-decision",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "actor": "auditor@example.com",
            "issue_key": "RG-1",
            "transition_id": "31",
            "project_id": "PROJ",
            "workflow_id": "wf-release",
            "environment": "prod",
            "context": {"org_id": "tenant-registry-api"},
        },
    )
    assert simulate_resp.status_code == 200, simulate_resp.text
    simulated = simulate_resp.json()
    assert simulated["allow"] is False
    assert simulated["status"] == "BLOCKED"
    assert "POLICY_DENIED" in simulated["reason_codes"]
    assert len(simulated["component_policy_ids"]) >= 1


def test_policy_registry_api_blocks_activation_when_lint_errors_exist():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api")

    create_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "2",
            "status": "DRAFT",
            "policy_json": {
                "strict_fail_closed": True,
                "required_transitions": ["2"],
                "transition_rules": [],
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    created = create_resp.json()
    assert created["lint_errors"]

    activate_resp = client.post(
        f"/policies/{created['policy_id']}/activate",
        headers=headers,
        json={"tenant_id": "tenant-registry-api"},
    )
    assert activate_resp.status_code == 400
    assert "lint errors" in activate_resp.text.lower()


def test_simulate_decision_endpoint_has_no_persistence_side_effects():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api")

    create_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "31",
            "status": "ACTIVE",
            "policy_json": {
                "strict_fail_closed": True,
                "transition_rules": [{"transition_id": "31", "result": "ALLOW"}],
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text

    before_decisions = _table_count("audit_decisions")
    before_idempotency = _table_count("idempotency_keys")
    before_security = _table_count("security_audit_events")

    simulate_resp = client.post(
        "/simulate-decision",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "issue_key": "RG-31",
            "transition_id": "31",
            "project_id": "PROJ",
            "workflow_id": "wf-release",
            "environment": "prod",
            "context": {"org_id": "tenant-registry-api"},
        },
    )
    assert simulate_resp.status_code == 200, simulate_resp.text

    assert _table_count("audit_decisions") == before_decisions
    assert _table_count("idempotency_keys") == before_idempotency
    assert _table_count("security_audit_events") == before_security
