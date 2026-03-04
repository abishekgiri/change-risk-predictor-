from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from releasegate.audit.recorder import AuditRecorder
from releasegate.config import DB_PATH
from releasegate.decision.types import Decision, DecisionType, EnforcementTargets, ExternalKeys, PolicyBinding
from releasegate.integrations.jira.decision_linkage import register_transition_decision_link
from releasegate.security.webhook_keys import create_webhook_key
from releasegate.server import app
from releasegate.storage import get_storage_backend
from releasegate.storage.schema import init_db


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _seed_allowed_decision_and_link(*, tenant_id: str, decision_id: str = "decision-allow-1") -> str:
    decision = Decision(
        decision_id=decision_id,
        tenant_id=tenant_id,
        timestamp=datetime.now(timezone.utc),
        release_status=DecisionType.ALLOWED,
        context_id=f"jira:{tenant_id}:RG-10:31",
        actor_id="acct-10",
        policy_bundle_hash="bundle-hash-1",
        policy_bindings=[
            PolicyBinding(
                policy_id="policy.release.prod",
                policy_version="7",
                policy_hash="policy-hash-7",
                tenant_id=tenant_id,
                policy={"id": "policy.release.prod", "version": "7"},
            )
        ],
        enforcement_targets=EnforcementTargets(
            repository="org/repo",
            pr_number=10,
            ref="abc123",
            external=ExternalKeys(jira=["RG-10"]),
        ),
        message="ALLOWED: policy passed",
    )
    AuditRecorder.record_with_context(decision, repo="org/repo", pr_number=10, tenant_id=tenant_id)
    register_transition_decision_link(
        tenant_id=tenant_id,
        decision_id=decision.decision_id,
        issue_key="RG-10",
        transition_id="31",
        actor_account_id="acct-10",
        source_status="In Progress",
        target_status="Done",
        environment="PRODUCTION",
        project_key="RG",
    )
    return decision.decision_id


def _signed_headers(*, tenant_id: str, payload_text: str) -> dict:
    secret = f"decision-linkage-secret-{tenant_id}"
    key = create_webhook_key(
        tenant_id=tenant_id,
        integration_id="jira",
        created_by="tests",
        raw_secret=secret,
        deactivate_existing=True,
    )
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{uuid.uuid4().hex[:12]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/integrations/jira/transition/authorize", payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Key-Id": key["key_id"],
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "Idempotency-Key": f"idem-{uuid.uuid4().hex[:16]}",
    }


def _post_authorize(*, tenant_id: str, payload: dict):
    payload_text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return client.post(
        "/integrations/jira/transition/authorize",
        content=payload_text.encode("utf-8"),
        headers=_signed_headers(tenant_id=tenant_id, payload_text=payload_text),
    )


def test_authorize_protected_transition_requires_decision_id():
    _reset_db()
    tenant_id = "tenant-linkage-required"
    payload = {
        "tenant_id": tenant_id,
        "issue_key": "RG-10",
        "transition_id": "31",
        "actor_account_id": "acct-10",
        "source_status": "In Progress",
        "target_status": "Done",
        "environment": "PRODUCTION",
        "project_key": "RG",
    }
    response = _post_authorize(tenant_id=tenant_id, payload=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is False
    assert body["reason_code"] == "DECISION_ID_REQUIRED"


def test_authorize_unknown_decision_is_blocked():
    _reset_db()
    tenant_id = "tenant-linkage-missing"
    payload = {
        "tenant_id": tenant_id,
        "issue_key": "RG-10",
        "transition_id": "31",
        "actor_account_id": "acct-10",
        "source_status": "In Progress",
        "target_status": "Done",
        "releasegate_decision_id": "missing-decision",
        "environment": "PRODUCTION",
        "project_key": "RG",
    }
    response = _post_authorize(tenant_id=tenant_id, payload=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is False
    assert body["reason_code"] == "DECISION_NOT_FOUND"


def test_authorize_matching_context_allows_and_consumes():
    _reset_db()
    tenant_id = "tenant-linkage-match"
    decision_id = _seed_allowed_decision_and_link(tenant_id=tenant_id)
    payload = {
        "tenant_id": tenant_id,
        "issue_key": "RG-10",
        "transition_id": "31",
        "actor_account_id": "acct-10",
        "source_status": "In Progress",
        "target_status": "Done",
        "releasegate_decision_id": decision_id,
        "environment": "PRODUCTION",
        "project_key": "RG",
        "request_id": "req-1",
    }
    response = _post_authorize(tenant_id=tenant_id, payload=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is True
    assert body["reason_code"] == "OK"


def test_authorize_context_mismatch_is_blocked():
    _reset_db()
    tenant_id = "tenant-linkage-mismatch"
    decision_id = _seed_allowed_decision_and_link(tenant_id=tenant_id)
    payload = {
        "tenant_id": tenant_id,
        "issue_key": "RG-10",
        "transition_id": "31",
        "actor_account_id": "other-actor",
        "source_status": "In Progress",
        "target_status": "Done",
        "releasegate_decision_id": decision_id,
        "environment": "PRODUCTION",
        "project_key": "RG",
    }
    response = _post_authorize(tenant_id=tenant_id, payload=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is False
    assert body["reason_code"] == "LINK_CONTEXT_MISMATCH"


def test_authorize_expired_link_is_blocked():
    _reset_db()
    tenant_id = "tenant-linkage-expired"
    decision_id = _seed_allowed_decision_and_link(tenant_id=tenant_id)
    storage = get_storage_backend()
    storage.execute(
        """
        UPDATE decision_transition_links
        SET expires_at = ?
        WHERE tenant_id = ? AND decision_id = ?
        """,
        ((datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(), tenant_id, decision_id),
    )
    payload = {
        "tenant_id": tenant_id,
        "issue_key": "RG-10",
        "transition_id": "31",
        "actor_account_id": "acct-10",
        "source_status": "In Progress",
        "target_status": "Done",
        "releasegate_decision_id": decision_id,
        "environment": "PRODUCTION",
        "project_key": "RG",
    }
    response = _post_authorize(tenant_id=tenant_id, payload=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is False
    assert body["reason_code"] == "LINK_EXPIRED"


def test_authorize_single_use_enforced_and_idempotent_request_allowed():
    _reset_db()
    tenant_id = "tenant-linkage-consume"
    decision_id = _seed_allowed_decision_and_link(tenant_id=tenant_id)
    payload = {
        "tenant_id": tenant_id,
        "issue_key": "RG-10",
        "transition_id": "31",
        "actor_account_id": "acct-10",
        "source_status": "In Progress",
        "target_status": "Done",
        "releasegate_decision_id": decision_id,
        "environment": "PRODUCTION",
        "project_key": "RG",
        "request_id": "req-consume-1",
    }
    first = _post_authorize(tenant_id=tenant_id, payload=payload)
    second_same_request = _post_authorize(tenant_id=tenant_id, payload=payload)

    payload["request_id"] = "req-consume-2"
    third_different_request = _post_authorize(tenant_id=tenant_id, payload=payload)

    assert first.status_code == 200
    assert first.json()["allow"] is True
    assert first.json()["reason_code"] == "OK"

    assert second_same_request.status_code == 200
    assert second_same_request.json()["allow"] is True
    assert second_same_request.json()["reason_code"] == "OK_IDEMPOTENT"

    assert third_different_request.status_code == 200
    assert third_different_request.json()["allow"] is False
    assert third_different_request.json()["reason_code"] == "LINK_ALREADY_CONSUMED"


def test_authorize_cross_tenant_reuse_is_blocked():
    _reset_db()
    owner_tenant = "tenant-linkage-owner"
    other_tenant = "tenant-linkage-other"
    decision_id = _seed_allowed_decision_and_link(tenant_id=owner_tenant, decision_id="decision-cross-tenant")
    payload = {
        "tenant_id": other_tenant,
        "issue_key": "RG-10",
        "transition_id": "31",
        "actor_account_id": "acct-10",
        "source_status": "In Progress",
        "target_status": "Done",
        "releasegate_decision_id": decision_id,
        "environment": "PRODUCTION",
        "project_key": "RG",
    }
    response = _post_authorize(tenant_id=other_tenant, payload=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is False
    assert body["reason_code"] == "DECISION_NOT_FOUND"
