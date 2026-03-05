from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.quota import QUOTA_KIND_DECISIONS, QUOTA_KIND_OVERRIDES, consume_tenant_quota
from releasegate.quota.quota_models import TenantQuotaExceededError
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


def _insert_decision_for_storage(*, tenant_id: str, decision_id: str) -> None:
    created_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "reason_code": "POLICY_BLOCKED",
        "input_snapshot": {
            "request": {
                "issue_key": f"RG-{decision_id}",
                "transition_id": "31",
                "actor_account_id": "acct-saas",
                "environment": "prod",
                "project_key": "PAYMENTS",
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
                created_at,
                f"eval-{decision_id}",
            ),
        )
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
                f"ovr-{decision_id}",
                "org/repo",
                1,
                f"RG-{decision_id}",
                decision_id,
                "acct-saas",
                "Emergency override",
                "transition",
                "31",
                f"idem-{decision_id}",
                "prev-hash",
                f"event-hash-{decision_id}",
                3600,
                (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "acct-saas",
                "acct-admin",
                created_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_dashboard_tenant_create_and_info_exposes_plan_and_limits():
    _reset_db()
    tenant_id = "tenant-saas-create"

    create_response = client.post(
        "/dashboard/tenant/create",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={
            "tenant_id": tenant_id,
            "name": "Acme Corp",
            "plan": "starter",
            "region": "eu-west",
        },
    )
    assert create_response.status_code == 200, create_response.text
    create_envelope, create_payload = _unwrap_dashboard_envelope(create_response)
    assert create_payload["trace_id"] == create_envelope["trace_id"]
    assert create_payload["tenant_id"] == tenant_id
    assert create_payload["name"] == "Acme Corp"
    assert create_payload["plan"] == "starter"
    assert create_payload["region"] == "eu-west"
    assert create_payload["status"] == "active"
    assert create_payload["limits"]["decision_limit_month"] == 5000
    assert create_payload["limits"]["override_limit_month"] == 200
    assert create_payload["limits"]["simulation_history_days"] == 7

    info_response = client.get(
        "/dashboard/tenant/info",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"], roles=["admin"]),
    )
    assert info_response.status_code == 200, info_response.text
    _, info_payload = _unwrap_dashboard_envelope(info_response)
    assert info_payload["tenant_id"] == tenant_id
    assert info_payload["plan"] == "starter"


def test_dashboard_tenant_role_assignment_and_status_updates():
    _reset_db()
    tenant_id = "tenant-saas-roles"

    create_response = client.post(
        "/dashboard/tenant/create",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={
            "tenant_id": tenant_id,
            "name": "Role Tenant",
            "plan": "growth",
            "region": "us-east",
        },
    )
    assert create_response.status_code == 200

    role_assign = client.post(
        "/dashboard/tenant/role_assign",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={
            "tenant_id": tenant_id,
            "actor_id": "alice@example.com",
            "role": "auditor",
            "action": "assign",
        },
    )
    assert role_assign.status_code == 200, role_assign.text
    _, role_payload = _unwrap_dashboard_envelope(role_assign)
    assert any(entry["actor_id"] == "alice@example.com" for entry in role_payload["roles"])

    lock_response = client.post(
        "/dashboard/tenant/lock",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={"tenant_id": tenant_id, "status": "locked", "reason": "manual test"},
    )
    assert lock_response.status_code == 200, lock_response.text
    _, lock_payload = _unwrap_dashboard_envelope(lock_response)
    assert lock_payload["status"] == "locked"

    throttle_response = client.post(
        "/dashboard/tenant/lock",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={"tenant_id": tenant_id, "status": "throttled", "reason": "capacity"},
    )
    assert throttle_response.status_code == 200, throttle_response.text
    _, throttle_payload = _unwrap_dashboard_envelope(throttle_response)
    assert throttle_payload["status"] == "throttled"

    unlock_response = client.post(
        "/dashboard/tenant/unlock",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={"tenant_id": tenant_id, "reason": "manual unlock"},
    )
    assert unlock_response.status_code == 200, unlock_response.text
    _, unlock_payload = _unwrap_dashboard_envelope(unlock_response)
    assert unlock_payload["status"] == "active"


def test_dashboard_tenant_key_rotation_and_plan_limit_enforcement():
    _reset_db()
    tenant_id = "tenant-saas-rotate"

    create_response = client.post(
        "/dashboard/tenant/create",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={
            "tenant_id": tenant_id,
            "name": "Rotate Tenant",
            "plan": "starter",
            "region": "us-east",
        },
    )
    assert create_response.status_code == 200

    rotate_response = client.post(
        "/dashboard/tenant/key_rotate",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={
            "tenant_id": tenant_id,
            "rotate_signing_key": True,
            "rotate_api_key": False,
        },
    )
    assert rotate_response.status_code == 200, rotate_response.text
    _, rotate_payload = _unwrap_dashboard_envelope(rotate_response)
    assert rotate_payload["tenant_id"] == tenant_id
    assert rotate_payload["rotated_signing_key_id"]

    simulation_response = client.post(
        "/simulation/run",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"], roles=["admin"]),
        json={"tenant_id": tenant_id, "lookback_days": 30},
    )
    assert simulation_response.status_code == 400
    assert "lookback_days exceeds plan limit" in str(simulation_response.json())


def test_dashboard_billing_usage_and_quota_caps():
    _reset_db()
    tenant_id = "tenant-saas-billing"

    create_response = client.post(
        "/dashboard/tenant/create",
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:write"], roles=["admin"]),
        json={
            "tenant_id": tenant_id,
            "name": "Billing Tenant",
            "plan": "starter",
            "region": "us-east",
        },
    )
    assert create_response.status_code == 200

    consume_tenant_quota(tenant_id=tenant_id, quota_kind=QUOTA_KIND_DECISIONS, amount=10)
    consume_tenant_quota(tenant_id=tenant_id, quota_kind=QUOTA_KIND_OVERRIDES, amount=3)
    _insert_decision_for_storage(tenant_id=tenant_id, decision_id="dec-billing-1")

    usage_response = client.get(
        "/dashboard/billing/usage",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"], roles=["admin"]),
    )
    assert usage_response.status_code == 200, usage_response.text
    _, usage_payload = _unwrap_dashboard_envelope(usage_response)
    assert usage_payload["tenant_id"] == tenant_id
    assert usage_payload["plan"] == "starter"
    assert usage_payload["decisions_this_month"] >= 10
    assert usage_payload["decision_limit"] == 5000
    assert usage_payload["overrides_this_month"] >= 3
    assert usage_payload["override_limit"] == 200
    assert usage_payload["storage_mb"] >= 0

    with_error = False
    try:
        consume_tenant_quota(tenant_id=tenant_id, quota_kind=QUOTA_KIND_DECISIONS, amount=6000)
    except TenantQuotaExceededError:
        with_error = True
    assert with_error is True
