from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from releasegate.integrations.jira.override_validation import ACTION_OVERRIDE, validate_override_request
from releasegate.integrations.jira.types import TransitionCheckResponse
from releasegate.security.webhook_keys import create_webhook_key
from releasegate.server import app


client = TestClient(app)


def _transition_payload() -> dict:
    return {
        "issue_key": "RG-VAL-1",
        "transition_id": "31",
        "source_status": "In Progress",
        "target_status": "Done",
        "actor_account_id": "acct-override",
        "actor_email": "override@example.com",
        "environment": "PRODUCTION",
        "project_key": "RG",
        "issue_type": "Story",
        "tenant_id": "tenant-test",
        "context_overrides": {},
    }


def _signed_headers(payload: dict, *, secret: str, key_id: str) -> dict:
    payload_text = json.dumps(payload)
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{uuid.uuid4().hex[:8]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/integrations/jira/transition/check", payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Key-Id": key_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "Idempotency-Key": f"idem-{uuid.uuid4().hex[:12]}",
    }


def test_override_validation_rejects_missing_ttl():
    result = validate_override_request(
        action=ACTION_OVERRIDE,
        ttl_seconds=None,
        justification="Emergency override approved by release governance team.",
        actor_roles=["admin"],
        idempotency_key="idem-1",
    )
    assert result.allowed is False
    assert result.reason_code == "OVERRIDE_TTL_REQUIRED"


def test_override_validation_rejects_non_admin():
    result = validate_override_request(
        action=ACTION_OVERRIDE,
        ttl_seconds=600,
        justification="Emergency override approved by release governance team.",
        actor_roles=["operator"],
        idempotency_key="idem-2",
    )
    assert result.allowed is False
    assert result.reason_code == "OVERRIDE_ADMIN_REQUIRED"


def test_transition_check_override_missing_ttl_is_blocked_at_api_boundary(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_SIGNATURE_DEFAULT_ROLES", "admin")
    monkeypatch.setenv("RELEASEGATE_SIGNATURE_DEFAULT_SCOPES", "enforcement:write")
    secret = "jira-override-validation-secret-1"
    key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="jira",
        created_by="test-suite",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload = _transition_payload()
    payload["context_overrides"] = {
        "override": True,
        "override_reason": "Emergency override approved by release governance team.",
    }
    response = client.post(
        "/integrations/jira/transition/check",
        content=json.dumps(payload).encode("utf-8"),
        headers=_signed_headers(payload, secret=secret, key_id=key["key_id"]),
    )
    assert response.status_code == 400
    body = response.json()
    assert body["detail"]["error_code"] == "OVERRIDE_TTL_REQUIRED"


def test_transition_check_override_non_admin_is_forbidden_at_api_boundary(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_SIGNATURE_DEFAULT_ROLES", "operator")
    monkeypatch.setenv("RELEASEGATE_SIGNATURE_DEFAULT_SCOPES", "enforcement:write")
    secret = "jira-override-validation-secret-2"
    key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="jira",
        created_by="test-suite",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload = _transition_payload()
    payload["context_overrides"] = {
        "override": True,
        "override_reason": "Emergency override approved by release governance team.",
        "override_ttl_seconds": 600,
    }
    response = client.post(
        "/integrations/jira/transition/check",
        content=json.dumps(payload).encode("utf-8"),
        headers=_signed_headers(payload, secret=secret, key_id=key["key_id"]),
    )
    assert response.status_code == 403
    body = response.json()
    assert body["detail"]["error_code"] == "OVERRIDE_ADMIN_REQUIRED"


def test_transition_check_override_sets_server_derived_expiry(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_SIGNATURE_DEFAULT_ROLES", "admin")
    monkeypatch.setenv("RELEASEGATE_SIGNATURE_DEFAULT_SCOPES", "enforcement:write")
    secret = "jira-override-validation-secret-3"
    key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="jira",
        created_by="test-suite",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload = _transition_payload()
    payload["context_overrides"] = {
        "override": True,
        "override_reason": "Emergency override approved by release governance team.",
        "override_ttl_seconds": 900,
        "override_expires_at": "1999-01-01T00:00:00Z",  # must be ignored
    }

    captured = {}

    def _fake_check(self, request):
        captured["override_expires_at"] = request.context_overrides.get("override_expires_at")
        captured["override_ttl_seconds"] = request.context_overrides.get("override_ttl_seconds")
        return TransitionCheckResponse(
            allow=True,
            reason="ALLOWED",
            decision_id="decision-override-valid",
            status="ALLOWED",
            reason_code="POLICY_ALLOWED",
            policy_hash="policy-hash",
            tenant_id=request.tenant_id,
        )

    with patch("releasegate.integrations.jira.routes.WorkflowGate.check_transition", _fake_check):
        response = client.post(
            "/integrations/jira/transition/check",
            content=json.dumps(payload).encode("utf-8"),
            headers=_signed_headers(payload, secret=secret, key_id=key["key_id"]),
        )
    assert response.status_code == 200
    assert captured["override_ttl_seconds"] == 900
    assert isinstance(captured["override_expires_at"], str)
    assert captured["override_expires_at"] != "1999-01-01T00:00:00Z"
