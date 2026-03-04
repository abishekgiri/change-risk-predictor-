from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.audit.overrides import record_override
from releasegate.integrations.jira.lock_store import apply_transition_lock_update, verify_lock_chain
from releasegate.server import app
from releasegate.storage import get_storage_backend
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _seed_high_risk_decision(*, tenant_id: str, decision_id: str) -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO audit_decisions (
            tenant_id, decision_id, context_id, repo, pr_number, release_status, policy_bundle_hash,
            engine_version, decision_hash, input_hash, policy_hash, replay_hash, full_decision_json, created_at, evaluation_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            decision_id,
            f"ctx-{decision_id}",
            "abishekgiri/change-risk-predictor-",
            28,
            "BLOCKED",
            "policy-hash",
            "test",
            "decision-hash",
            "input-hash",
            "policy-hash",
            "replay-hash",
            json.dumps({"risk_level": "HIGH", "risk_score": 0.91}),
            datetime.now(timezone.utc).isoformat(),
            f"eval-{decision_id}",
        ),
    )


def setup_function(_):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def teardown_function(_):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def test_create_and_verify_jira_lock_checkpoint(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "jira-lock-checkpoint-test-key")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID", "test-key")
    tenant = "tenant-test"
    issue = f"RG-CP-{uuid.uuid4().hex[:8]}"
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=True,
        reason_codes=["POLICY_BLOCKED"],
        decision_id="d-lock-cp-1",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="abishekgiri/change-risk-predictor-",
        pr_number=28,
        actor="admin@example.com",
        context={"transition_id": "2"},
    )

    create_resp = client.post(
        "/audit/checkpoints/jira-lock",
        params={"tenant_id": tenant, "chain_id": f"jira-lock:{issue}", "cadence": "daily"},
        headers=jwt_headers(roles=["admin"], scopes=["checkpoint:read"]),
    )
    assert create_resp.status_code == 200
    body = create_resp.json()
    period_id = body["payload"]["period_id"]

    verify_resp = client.get(
        "/audit/checkpoints/jira-lock/verify",
        params={
            "tenant_id": tenant,
            "chain_id": f"jira-lock:{issue}",
            "cadence": "daily",
            "period_id": period_id,
        },
        headers=jwt_headers(roles=["auditor"], scopes=["checkpoint:read"]),
    )
    assert verify_resp.status_code == 200
    verified = verify_resp.json()
    assert verified["exists"] is True
    assert verified["valid"] is True
    assert verified["checkpoint_hash_match"] is True
    assert verified["head_hash_match"] is True

    latest_resp = client.get(
        "/audit/checkpoints/jira-lock/latest",
        params={"tenant_id": tenant, "chain_id": f"jira-lock:{issue}", "cadence": "daily"},
        headers=jwt_headers(roles=["auditor"], scopes=["checkpoint:read"]),
    )
    assert latest_resp.status_code == 200
    latest = latest_resp.json()
    assert latest.get("ids", {}).get("checkpoint_id") == body.get("ids", {}).get("checkpoint_id")

    chain = verify_lock_chain(tenant_id=tenant, chain_id=f"jira-lock:{issue}")
    assert chain["valid"] is True
    assert chain["checked"] == 1


def test_governance_override_metrics_api_reports_core_fields():
    tenant = "tenant-test"
    issue = "RG-MET-1"
    decision_id = "d-metrics-high-risk"
    _seed_high_risk_decision(tenant_id=tenant, decision_id=decision_id)

    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=False,
        reason_codes=["OVERRIDE_APPLIED"],
        decision_id=decision_id,
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="abishekgiri/change-risk-predictor-",
        pr_number=28,
        actor="admin@example.com",
        override_expires_at=(datetime.now(timezone.utc)).isoformat(),
        override_reason="Emergency release override approved by admin team.",
        override_by="admin@example.com",
        ttl_seconds=1800,
        justification="Emergency release override approved by admin team.",
        context={"transition_id": "2"},
    )

    response = client.get(
        "/governance/override-metrics",
        params={"tenant_id": tenant, "days": 30, "top_n": 5},
        headers=jwt_headers(roles=["auditor"], scopes=["policy:read"]),
    )
    assert response.status_code == 200
    body = response.json()
    metrics = body["metrics"]
    assert metrics["overrides_total_30d"] >= 1
    assert metrics["overrides_total_7d"] >= 1
    assert metrics["high_risk_overrides_total_30d"] >= 1
    assert "overrides_by_actor_30d" in body


def test_latest_override_checkpoint_endpoint_returns_latest(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "override-checkpoint-test-key")
    tenant = "tenant-test"
    repo = f"checkpoint-api-{uuid.uuid4().hex[:8]}"
    pr_number = 28
    record_override(
        repo=repo,
        pr_number=pr_number,
        issue_key="RG-CP-OVR-1",
        decision_id="d-cp-ovr-1",
        actor="admin@example.com",
        reason="override checkpoint seed",
        tenant_id=tenant,
    )
    create_resp = client.post(
        "/audit/checkpoints/override",
        params={"tenant_id": tenant, "repo": repo, "pr": pr_number, "cadence": "daily"},
        headers=jwt_headers(roles=["admin"], scopes=["checkpoint:read"]),
    )
    assert create_resp.status_code == 200
    created = create_resp.json()

    latest_resp = client.get(
        "/audit/checkpoints/override/latest",
        params={"tenant_id": tenant, "repo": repo, "cadence": "daily"},
        headers=jwt_headers(roles=["auditor"], scopes=["checkpoint:read"]),
    )
    assert latest_resp.status_code == 200
    latest = latest_resp.json()
    assert latest.get("ids", {}).get("checkpoint_id") == created.get("ids", {}).get("checkpoint_id")
    assert str(((latest.get("payload") or {}).get("checkpoint_hash") or "")).startswith("sha256:")
