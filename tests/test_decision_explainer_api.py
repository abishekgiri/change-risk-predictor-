from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.policy.snapshots import (
    build_resolved_policy_snapshot,
    store_resolved_policy_snapshot,
    record_policy_decision_binding,
)
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _unwrap_dashboard_envelope(response) -> tuple[dict, dict]:
    body = response.json()
    assert body["generated_at"]
    assert body["trace_id"]
    payload = body["data"]
    assert isinstance(payload, dict)
    return body, payload


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _seed_decision_with_snapshot(*, tenant_id: str, decision_id: str) -> None:
    snapshot = build_resolved_policy_snapshot(
        policy_id="policy-prod",
        policy_version="2",
        resolution_inputs={"scope_type": "transition", "scope_id": "31"},
        resolved_policy={
            "strict_fail_closed": True,
            "transition_rules": [{"transition_id": "31", "result": "BLOCK"}],
        },
    )
    stored_snapshot = store_resolved_policy_snapshot(tenant_id=tenant_id, snapshot=snapshot)
    policy_hash = str(stored_snapshot.get("policy_hash") or "")

    full_decision = {
        "reason_code": "RISK_TOO_HIGH",
        "input_snapshot": {
            "request": {
                "issue_key": "RG-42",
                "transition_id": "31",
                "actor_account_id": "acct-explainer",
                "source_status": "In Progress",
                "target_status": "Done",
                "environment": "prod",
                "project_key": "PROJ",
                "context_overrides": {"workflow_id": "wf-release"},
            },
            "signal_map": {"risk": {"score": 0.91, "level": "HIGH"}},
            "risk_meta": {"risk_score": 0.91, "risk_level": "HIGH"},
        },
        "policy_bindings": [{"policy_id": "policy-prod", "policy_version": "2", "policy_hash": policy_hash}],
    }

    conn = sqlite3.connect(DB_PATH)
    try:
        now = datetime.now(timezone.utc).isoformat()
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
                policy_hash,
                f"replay-hash-{decision_id}",
                json.dumps(full_decision, separators=(",", ":"), sort_keys=True),
                now,
                f"eval-{decision_id}",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    record_policy_decision_binding(
        tenant_id=tenant_id,
        decision_id=decision_id,
        snapshot_id=str(stored_snapshot.get("snapshot_id") or ""),
        policy_hash=policy_hash,
        decision="DENY",
        reason_codes=["RISK_TOO_HIGH"],
        signal_bundle_hash="signal-bundle-1",
        issue_key="RG-42",
        transition_id="31",
        actor_id="acct-explainer",
    )


def test_dashboard_decision_explainer_returns_binding_and_replay_link():
    _reset_db()
    tenant_id = "tenant-decision-explainer"
    decision_id = "decision-explain-1"
    _seed_decision_with_snapshot(tenant_id=tenant_id, decision_id=decision_id)

    response = client.get(
        f"/dashboard/decisions/{decision_id}/explainer",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 200, response.text
    envelope, body = _unwrap_dashboard_envelope(response)
    assert body["trace_id"] == envelope["trace_id"]
    assert body["decision_id"] == decision_id
    assert body["decision"]["outcome"] == "BLOCK"
    assert body["decision"]["blocked_because"]
    assert body["decision"]["workflow_id"] == "wf-release"
    assert body["snapshot_binding"]["policy_hash"]
    assert body["snapshot_binding"]["snapshot_hash"]
    assert body["snapshot_binding"]["decision_hash"] == f"decision-hash-{decision_id}"
    assert isinstance(body["signals"], list)
    assert body["signals"][0]["name"] == "risk"
    assert "source" in body["signals"][0]
    assert "confidence" in body["signals"][0]
    assert isinstance(body["risk"]["components"], list)
    assert body["risk"]["score"] == 0.91
    assert isinstance(body["evidence_links"], list)
    assert body["replay"]["path"] == f"/decisions/{decision_id}/replay"
    assert body["replay"]["token"] == f"replay-hash-{decision_id}"
    assert "expires_at" in body["replay"]
    assert response.headers.get("X-Request-Id") == envelope["trace_id"]
    assert response.headers.get("Cache-Control") == "private, no-store"


def test_dashboard_decision_explainer_returns_404_for_missing_decision():
    _reset_db()
    tenant_id = "tenant-decision-explainer"
    response = client.get(
        "/dashboard/decisions/missing/explainer",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert response.status_code == 404
    body = response.json()
    assert body["generated_at"]
    assert body["trace_id"]
    assert body["error"]["code"] == "NOT_FOUND"
    assert body["error"]["error_code"] == "NOT_FOUND"
