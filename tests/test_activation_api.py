from __future__ import annotations

import os

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
