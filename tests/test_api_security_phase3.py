import uuid
from datetime import datetime, timezone
import hashlib
import hmac
import json
from unittest.mock import patch

import jwt
from fastapi.testclient import TestClient

from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets
from releasegate.security.webhook_keys import create_webhook_key
from releasegate.server import app
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _record_decision(repo: str, pr_number: int) -> Decision:
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="ALLOWED: security test",
        policy_bundle_hash="sec-test-hash",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="security-test",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={"signal_map": {"repo": repo, "pr_number": pr_number, "diff": {}}, "policies_requested": []},
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["SEC-1"]},
        ),
    )
    return AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)


def test_health_endpoint_is_public():
    resp = client.get("/")
    assert resp.status_code == 200


def test_ops_health_endpoint_is_public():
    resp = client.get("/health")
    assert resp.status_code == 200


def test_ci_score_allows_internal_service_key(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_KEY", "phase3-internal-service")
    with patch(
        "releasegate.server.get_pr_details",
        return_value={"changed_files": 3, "additions": 14, "deletions": 4},
    ):
        resp = client.post(
            "/ci/score",
            json={"repo": "org/repo", "pr": 27},
            headers={"X-Internal-Service-Key": "phase3-internal-service"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["level"] in {"LOW", "MEDIUM", "HIGH"}
    assert isinstance(body["score"], int)


def test_ci_score_internal_service_requires_tenant_context(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_INTERNAL_SERVICE_KEY", "phase3-internal-service")
    monkeypatch.setenv("RELEASEGATE_REQUIRE_TENANT_ID", "true")
    monkeypatch.delenv("RELEASEGATE_TENANT_ID", raising=False)
    monkeypatch.delenv("RELEASEGATE_INTERNAL_SERVICE_TENANT_ID", raising=False)
    response = client.post(
        "/ci/score",
        json={"repo": "org/repo", "pr": 27},
        headers={"X-Internal-Service-Key": "phase3-internal-service"},
    )
    assert response.status_code == 401
    detail = response.json().get("detail") or {}
    assert detail.get("error_code") == "AUTH_TENANT_REQUIRED"


def test_audit_export_requires_auth():
    resp = client.get("/audit/export", params={"repo": "any", "tenant_id": "tenant-test"})
    assert resp.status_code == 401


def test_proof_pack_export_forbidden_for_read_only_role():
    repo = f"sec-proof-{uuid.uuid4().hex[:8]}"
    stored = _record_decision(repo, 91)
    resp = client.get(
        f"/audit/proof-pack/{stored.decision_id}",
        params={"format": "json", "tenant_id": "tenant-test"},
        headers=jwt_headers(roles=["read_only"], scopes=["policy:read"]),
    )
    assert resp.status_code == 403


def test_policy_publish_requires_admin_role():
    resp = client.post(
        "/policy/publish",
        params={"tenant_id": "tenant-test"},
        json={"policy_bundle_hash": "bundle-x", "policy_snapshot": [], "activate": True},
        headers=jwt_headers(roles=["operator"], scopes=["policy:write"]),
    )
    assert resp.status_code == 403


def test_admin_can_create_api_key():
    resp = client.post(
        "/auth/api-keys",
        json={
            "name": "phase3-test-key",
            "roles": ["operator"],
            "scopes": ["enforcement:write", "policy:read"],
            "tenant_id": "tenant-test",
        },
        headers=jwt_headers(roles=["admin"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "tenant-test"
    assert body["key_id"]
    assert body["api_key"].startswith("rgk_")

    repo = f"sec-api-key-{uuid.uuid4().hex[:8]}"
    _record_decision(repo, 93)
    export_resp = client.get(
        "/audit/export",
        params={"repo": repo, "tenant_id": "tenant-test"},
        headers={"X-API-Key": body["api_key"]},
    )
    assert export_resp.status_code == 200


def test_api_key_rotation_revokes_previous_key():
    created = client.post(
        "/auth/api-keys",
        json={
            "name": "phase3-rotate-test-key",
            "roles": ["operator"],
            "scopes": ["policy:read"],
            "tenant_id": "tenant-test",
        },
        headers=jwt_headers(roles=["admin"]),
    )
    assert created.status_code == 200
    old = created.json()

    rotated_resp = client.post(
        f"/auth/api-keys/{old['key_id']}/rotate",
        json={"tenant_id": "tenant-test"},
        headers=jwt_headers(roles=["admin"]),
    )
    assert rotated_resp.status_code == 200
    rotated = rotated_resp.json()
    assert rotated["key_id"] != old["key_id"]
    assert rotated["rotated_from_key_id"] == old["key_id"]
    assert rotated["api_key"].startswith("rgk_")

    repo = f"sec-api-key-rotated-{uuid.uuid4().hex[:8]}"
    _record_decision(repo, 95)
    old_key_resp = client.get(
        "/audit/export",
        params={"repo": repo, "tenant_id": "tenant-test"},
        headers={"X-API-Key": old["api_key"]},
    )
    assert old_key_resp.status_code == 401

    new_key_resp = client.get(
        "/audit/export",
        params={"repo": repo, "tenant_id": "tenant-test"},
        headers={"X-API-Key": rotated["api_key"]},
    )
    assert new_key_resp.status_code == 200


def test_replay_endpoint_rate_limits_heavy_profile(monkeypatch):
    from releasegate.security import rate_limit

    repo = f"sec-replay-{uuid.uuid4().hex[:8]}"
    stored = _record_decision(repo, 92)

    monkeypatch.setitem(rate_limit.PROFILES, "heavy", (1, 100))
    headers = jwt_headers(roles=["auditor"], scopes=["policy:read"])

    first = client.post(
        f"/decisions/{stored.decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=headers,
    )
    assert first.status_code != 429

    second = client.post(
        f"/decisions/{stored.decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=headers,
    )
    assert second.status_code == 429


def test_webhook_signature_auth_and_replay_protection():
    secret = "phase3-signature-secret"
    key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="github",
        created_by="test-suite",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload = {"ping": True}
    payload_text = json.dumps(payload)
    payload_bytes = payload_text.encode("utf-8")
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{uuid.uuid4().hex[:8]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/webhooks/github", payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "X-Signature": signature,
        "X-Key-Id": key["key_id"],
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-GitHub-Event": "ping",
        "Content-Type": "application/json",
    }

    first = client.post("/webhooks/github", content=payload_bytes, headers=headers)
    assert first.status_code == 200
    assert first.json() == {"msg": "pong"}

    second = client.post("/webhooks/github", content=payload_bytes, headers=headers)
    assert second.status_code == 401


def test_webhook_signature_auth_accepts_rg_headers():
    secret = "phase3-rg-header-secret"
    key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="github",
        created_by="test-suite",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload = {"ping": True}
    payload_text = json.dumps(payload)
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{uuid.uuid4().hex[:8]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/webhooks/github", payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "X-RG-Signature": signature,
        "X-RG-Key-Id": key["key_id"],
        "X-RG-Timestamp": timestamp,
        "X-RG-Nonce": nonce,
        "X-GitHub-Event": "ping",
        "Content-Type": "application/json",
    }

    response = client.post("/webhooks/github", content=payload_text.encode("utf-8"), headers=headers)
    assert response.status_code == 200
    assert response.json() == {"msg": "pong"}


def test_webhook_signature_rejects_stale_timestamp():
    secret = "phase3-stale-secret"
    key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="github",
        created_by="test-suite",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload = {"ping": True}
    payload_text = json.dumps(payload)
    timestamp = str(int(datetime.now(timezone.utc).timestamp()) - 7200)
    nonce = f"nonce-{uuid.uuid4().hex[:8]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/webhooks/github", payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "X-Signature": signature,
        "X-Key-Id": key["key_id"],
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-GitHub-Event": "ping",
        "Content-Type": "application/json",
    }

    response = client.post("/webhooks/github", content=payload_text.encode("utf-8"), headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"]["error_code"] == "AUTH_SIGNATURE_STALE"


def test_webhook_rejects_jwt_even_if_valid():
    response = client.post(
        "/webhooks/github",
        json={"ping": True},
        headers={
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json",
            **jwt_headers(scopes=["enforcement:write"]),
        },
    )
    assert response.status_code == 401
    body = response.json()
    assert body["detail"]["error_code"] == "AUTH_SIGNATURE_REQUIRED"


def test_webhook_rejects_mixed_auth_methods():
    secret = "phase3-mixed-secret"
    key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="github",
        created_by="test-suite",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload = {"ping": True}
    payload_text = json.dumps(payload)
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{uuid.uuid4().hex[:8]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/webhooks/github", payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    response = client.post(
        "/webhooks/github",
        content=payload_text.encode("utf-8"),
        headers={
            "X-Signature": signature,
            "X-Key-Id": key["key_id"],
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json",
            **jwt_headers(scopes=["enforcement:write"]),
        },
    )
    assert response.status_code == 401
    body = response.json()
    assert body["detail"]["error_code"] == "AUTH_MIXED_METHODS"


def test_jwt_missing_required_claims_is_rejected():
    token = jwt.encode(
        {
            "sub": "missing-claims-user",
            "tenant_id": "tenant-test",
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "iss": "releasegate",
        },
        "test-jwt-secret",
        algorithm="HS256",
    )
    response = client.get(
        "/audit/export",
        params={"repo": "any", "tenant_id": "tenant-test"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    body = response.json()
    assert body["detail"]["error_code"] == "AUTH_JWT_INVALID"
