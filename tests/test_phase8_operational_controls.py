from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.integrations.jira.types import TransitionCheckResponse
from releasegate.quota import (
    QUOTA_KIND_ANCHORS,
    QUOTA_KIND_DECISIONS,
    QUOTA_KIND_OVERRIDES,
    consume_tenant_quota,
)
from releasegate.security.rate_limit import reset_rate_limits
from releasegate.security.security_state_service import (
    SECURITY_STATE_LOCKED,
    SECURITY_STATE_THROTTLED,
    set_tenant_security_state,
)
from releasegate.security.webhook_keys import create_webhook_key
from releasegate.server import app
from releasegate.storage import get_storage_backend
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    reset_rate_limits()


def _transition_payload(tenant_id: str) -> dict:
    return {
        "issue_key": "RG-P8-1",
        "transition_id": "31",
        "source_status": "In Progress",
        "target_status": "Done",
        "actor_account_id": "acct-phase8",
        "actor_email": "phase8@example.com",
        "environment": "PRODUCTION",
        "project_key": "RG",
        "issue_type": "Story",
        "tenant_id": tenant_id,
        "context_overrides": {},
    }


def _signed_headers(payload: dict, *, secret: str, key_id: str) -> dict:
    payload_text = json.dumps(payload)
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{uuid.uuid4().hex[:12]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/integrations/jira/transition/check", payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Key-Id": key_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "Idempotency-Key": f"idem-{uuid.uuid4().hex[:16]}",
    }


def test_decision_quota_exceeded_blocks_transition_check(monkeypatch):
    _reset_db()
    tenant_id = "tenant-p8-decisions"
    monkeypatch.setenv("RELEASEGATE_SIGNATURE_DEFAULT_ROLES", "admin")
    monkeypatch.setenv("RELEASEGATE_SIGNATURE_DEFAULT_SCOPES", "enforcement:write")

    admin_headers = jwt_headers(tenant_id=tenant_id, roles=["admin"]) 
    updated = client.put(
        f"/tenants/{tenant_id}/governance-settings",
        json={
            "max_decisions_per_month": 1,
            "quota_enforcement_mode": "HARD",
        },
        headers=admin_headers,
    )
    assert updated.status_code == 200

    secret = "phase8-decision-quota-secret"
    key = create_webhook_key(
        tenant_id=tenant_id,
        integration_id="jira",
        created_by="tests",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload = _transition_payload(tenant_id)

    def _fake_check(self, request):
        return TransitionCheckResponse(
            allow=True,
            reason="ALLOWED",
            decision_id=f"decision-{uuid.uuid4().hex[:8]}",
            status="ALLOWED",
            reason_code="POLICY_ALLOWED",
            policy_hash="policy-hash",
            tenant_id=request.tenant_id,
        )

    with patch("releasegate.integrations.jira.routes.WorkflowGate.check_transition", _fake_check):
        body = json.dumps(payload).encode("utf-8")
        first = client.post(
            "/integrations/jira/transition/check",
            content=body,
            headers=_signed_headers(payload, secret=secret, key_id=key["key_id"]),
        )
        second = client.post(
            "/integrations/jira/transition/check",
            content=body,
            headers=_signed_headers(payload, secret=secret, key_id=key["key_id"]),
        )

    assert first.status_code == 200
    assert second.status_code == 429
    detail = second.json().get("detail") or {}
    assert detail.get("error") == "TENANT_QUOTA_EXCEEDED"
    assert detail.get("quota") == QUOTA_KIND_DECISIONS


def test_override_quota_exceeded_blocks_manual_override():
    _reset_db()
    tenant_id = "tenant-p8-overrides"
    admin_headers = {
        **jwt_headers(tenant_id=tenant_id, roles=["admin"]),
        "Idempotency-Key": f"idem-{uuid.uuid4().hex[:16]}",
    }

    updated = client.put(
        f"/tenants/{tenant_id}/governance-settings",
        json={
            "max_overrides_per_month": 0,
            "quota_enforcement_mode": "HARD",
        },
        headers=jwt_headers(tenant_id=tenant_id, roles=["admin"]),
    )
    assert updated.status_code == 200

    response = client.post(
        "/audit/overrides",
        json={
            "repo": "demo/repo",
            "pr_number": 10,
            "reason": "Emergency override approved by governance",
            "ttl_seconds": 600,
        },
        headers=admin_headers,
    )
    assert response.status_code == 429
    detail = response.json().get("detail") or {}
    assert detail.get("error") == "TENANT_QUOTA_EXCEEDED"
    assert detail.get("quota") == QUOTA_KIND_OVERRIDES


def test_locked_tenant_blocks_state_change_and_unlock_restores_access():
    _reset_db()
    tenant_id = "tenant-p8-lock"
    admin_headers = jwt_headers(tenant_id=tenant_id, roles=["admin"])

    set_tenant_security_state(
        tenant_id=tenant_id,
        to_state=SECURITY_STATE_LOCKED,
        reason="test lock",
        source="test",
        actor="tester",
    )

    blocked = client.post(
        "/auth/api-keys",
        json={"name": "blocked-key"},
        headers=admin_headers,
    )
    assert blocked.status_code == 423
    detail = blocked.json().get("detail") or {}
    assert detail.get("error") == "TENANT_LOCKED"

    read_allowed = client.get(f"/tenants/{tenant_id}/compromise-report", headers=admin_headers)
    assert read_allowed.status_code == 200

    unlocked = client.post(
        f"/tenants/{tenant_id}/unlock",
        json={"reason": "incident resolved"},
        headers=admin_headers,
    )
    assert unlocked.status_code == 200
    assert unlocked.json().get("to_state") == "normal"

    allowed = client.post(
        "/auth/api-keys",
        json={"name": "allowed-key"},
        headers=admin_headers,
    )
    assert allowed.status_code == 200


def test_throttled_tenant_reduces_rate_limit(monkeypatch):
    _reset_db()
    tenant_id = "tenant-p8-throttle"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin"])

    set_tenant_security_state(
        tenant_id=tenant_id,
        to_state=SECURITY_STATE_THROTTLED,
        reason="test throttle",
        source="test",
        actor="tester",
    )
    monkeypatch.setenv("RELEASEGATE_THROTTLED_RATE_FACTOR", "0.05")

    first = client.get("/audit/search", headers=headers)
    second = client.get("/audit/search", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 429
    detail = second.json().get("detail") or {}
    assert detail.get("error_code") == "RATE_LIMIT_TENANT"


def test_governance_metrics_endpoint_reports_usage_and_state():
    _reset_db()
    tenant_id = "tenant-p8-metrics"
    headers = jwt_headers(tenant_id=tenant_id, roles=["auditor"])

    consume_tenant_quota(tenant_id=tenant_id, quota_kind=QUOTA_KIND_DECISIONS, amount=3)
    consume_tenant_quota(tenant_id=tenant_id, quota_kind=QUOTA_KIND_OVERRIDES, amount=2)
    consume_tenant_quota(tenant_id=tenant_id, quota_kind=QUOTA_KIND_ANCHORS, amount=1)
    set_tenant_security_state(
        tenant_id=tenant_id,
        to_state=SECURITY_STATE_THROTTLED,
        reason="test metrics state",
        source="test",
        actor="tester",
    )

    response = client.get(f"/tenants/{tenant_id}/governance-metrics", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == tenant_id
    assert body["decisions_month"] == 3
    assert body["overrides_month"] == 2
    assert body["anchors_today"] == 1
    assert body["security_state"] == "throttled"
    assert "deny_rate" in body


def test_usage_counters_reset_on_period_boundary():
    _reset_db()
    tenant_id = "tenant-p8-period-reset"
    jan = datetime(2026, 1, 31, 23, 59, tzinfo=timezone.utc)
    feb = datetime(2026, 2, 1, 0, 1, tzinfo=timezone.utc)

    consume_tenant_quota(
        tenant_id=tenant_id,
        quota_kind=QUOTA_KIND_DECISIONS,
        amount=1,
        now=jan,
    )
    consume_tenant_quota(
        tenant_id=tenant_id,
        quota_kind=QUOTA_KIND_DECISIONS,
        amount=1,
        now=feb,
    )

    rows = get_storage_backend().fetchall(
        """
        SELECT period_type, period_start, decisions_count
        FROM tenant_usage_counters
        WHERE tenant_id = ? AND period_type = 'monthly'
        ORDER BY period_start ASC
        """,
        (tenant_id,),
    )
    assert len(rows) == 2
    assert int(rows[0]["decisions_count"]) == 1
    assert int(rows[1]["decisions_count"]) == 1


def test_quota_counters_are_tenant_isolated():
    _reset_db()
    tenant_a = "tenant-p8-quota-a"
    tenant_b = "tenant-p8-quota-b"

    consume_tenant_quota(tenant_id=tenant_a, quota_kind=QUOTA_KIND_DECISIONS, amount=2)
    consume_tenant_quota(tenant_id=tenant_b, quota_kind=QUOTA_KIND_DECISIONS, amount=1)

    metrics_a = client.get(f"/tenants/{tenant_a}/governance-metrics", headers=jwt_headers(tenant_id=tenant_a, roles=["auditor"]))
    metrics_b = client.get(f"/tenants/{tenant_b}/governance-metrics", headers=jwt_headers(tenant_id=tenant_b, roles=["auditor"]))
    assert metrics_a.status_code == 200
    assert metrics_b.status_code == 200
    assert metrics_a.json()["decisions_month"] == 2
    assert metrics_b.json()["decisions_month"] == 1
