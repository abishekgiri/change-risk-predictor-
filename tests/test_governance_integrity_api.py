from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

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


def _insert_policy_entry(
    *,
    tenant_id: str,
    scope_type: str,
    scope_id: str,
    version: int,
    created_at: datetime,
    policy_json: dict,
    status: str = "ACTIVE",
) -> str:
    policy_id = f"policy-{scope_type}-{scope_id}-v{version}-{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO policy_registry_entries (
                tenant_id, policy_id, scope_type, scope_id, version, status,
                policy_json, policy_hash, lint_errors_json, lint_warnings_json,
                rollout_percentage, rollout_scope,
                created_at, created_by, activated_at, activated_by, supersedes_policy_id, archived_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', 100, NULL, ?, 'tests', ?, 'tests', NULL, ?)
            """,
            (
                tenant_id,
                policy_id,
                scope_type,
                scope_id,
                int(version),
                str(status).upper(),
                json.dumps(policy_json, separators=(",", ":"), sort_keys=True),
                f"sha256:{uuid.uuid4().hex}",
                created_at.isoformat(),
                created_at.isoformat(),
                created_at.isoformat() if str(status).upper() == "ARCHIVED" else None,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return policy_id


def _decision_payload(*, reason_code: str, transition_id: str = "31", target_status: str = "Done") -> str:
    payload = {
        "release_status": "ALLOWED" if reason_code == "POLICY_ALLOWED" else "BLOCKED",
        "reason_code": reason_code,
        "input_snapshot": {
            "request": {
                "issue_key": "RG-1",
                "transition_id": transition_id,
                "actor_account_id": "acct-governance",
                "source_status": "In Progress",
                "target_status": target_status,
                "environment": "prod",
                "project_key": "PROJ",
                "context_overrides": {"workflow_id": "wf-release"},
            },
            "signal_map": {"risk": {"score": 0.82}},
        },
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _insert_decision(
    *,
    tenant_id: str,
    decision_id: str,
    created_at: datetime,
    release_status: str,
    reason_code: str,
    with_linkage: bool = True,
) -> None:
    payload_text = _decision_payload(reason_code=reason_code)
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
                release_status,
                "bundle-hash",
                "engine-v1",
                f"decision-hash-{decision_id}",
                f"input-hash-{decision_id}",
                "policy-hash",
                f"replay-hash-{decision_id}",
                payload_text,
                created_at.isoformat(),
                f"eval-{decision_id}",
            ),
        )
        if with_linkage:
            conn.execute(
                """
                INSERT INTO decision_transition_links (
                    tenant_id, decision_id, jira_issue_id, transition_id, actor,
                    source_status, target_status, policy_id, policy_version, policy_hash,
                    context_hash, expires_at, consumed, consumed_at, consumed_by_request_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?)
                """,
                (
                    tenant_id,
                    decision_id,
                    "RG-1",
                    "31",
                    "acct-governance",
                    "In Progress",
                    "Done",
                    "policy-current",
                    "2",
                    "policy-hash",
                    f"context-{decision_id}",
                    (created_at + timedelta(minutes=10)).isoformat(),
                    created_at.isoformat(),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _insert_override(*, tenant_id: str, decision_id: str, actor: str, created_at: datetime) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO audit_overrides (
                tenant_id, override_id, decision_id, repo, pr_number, issue_key,
                actor, reason, target_type, target_id, idempotency_key,
                previous_hash, event_hash, ttl_seconds, expires_at, requested_by, approved_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                f"ovr-{uuid.uuid4().hex[:12]}",
                decision_id,
                "org/repo",
                1,
                "RG-1",
                actor,
                "Emergency override",
                "pr",
                "org/repo#1",
                f"idem-{uuid.uuid4().hex[:12]}",
                None,
                f"hash-{uuid.uuid4().hex}",
                3600,
                (created_at + timedelta(hours=1)).isoformat(),
                actor,
                actor,
                created_at.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_failed_override_sod_anomaly(*, tenant_id: str, created_at: datetime) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO tenant_security_anomaly_events (
                tenant_id, event_id, signal_type, operation, details_json, created_at
            ) VALUES (?, ?, 'failed_override_attempt', 'jira_transition_check', ?, ?)
            """,
            (
                tenant_id,
                f"anom-{uuid.uuid4().hex[:12]}",
                json.dumps({"reason_code": "SOD_CONFLICT", "sod_rule": "no-self-approval"}, separators=(",", ":"), sort_keys=True),
                created_at.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_governance_integrity_endpoint_reports_drift_abuse_and_score():
    _reset_db()
    tenant_id = "tenant-phase12"
    now = datetime.now(timezone.utc)

    _insert_policy_entry(
        tenant_id=tenant_id,
        scope_type="transition",
        scope_id="31",
        version=1,
        created_at=now - timedelta(days=20),
        status="ARCHIVED",
        policy_json={
            "strict_fail_closed": True,
            "approval_requirements": {"min_approvals": 2, "required_roles": ["security", "em"]},
            "protected_statuses": ["Done", "Released"],
            "transition_rules": [{"rule_id": "prod-block", "transition_id": "31", "environment": "prod", "result": "BLOCK", "priority": 100}],
            "risk_thresholds": {"prod": {"max_score": 0.7}},
            "override_controls": {"max_ttl_seconds": 1800},
        },
    )
    _insert_policy_entry(
        tenant_id=tenant_id,
        scope_type="transition",
        scope_id="31",
        version=2,
        created_at=now - timedelta(days=5),
        policy_json={
            "strict_fail_closed": False,
            "approval_requirements": {"min_approvals": 1, "required_roles": ["security"]},
            "protected_statuses": ["Released"],
            "transition_rules": [{"rule_id": "prod-block", "transition_id": "31", "environment": "prod", "result": "ALLOW", "priority": 100}],
            "risk_thresholds": {"prod": {"max_score": 0.9}},
            "override_controls": {"max_ttl_seconds": 7200},
        },
    )

    decision_ids = []
    for i in range(10):
        decision_id = f"dec-{uuid.uuid4().hex[:10]}"
        decision_ids.append(decision_id)
        _insert_decision(
            tenant_id=tenant_id,
            decision_id=decision_id,
            created_at=now - timedelta(days=1, minutes=i),
            release_status="ALLOWED" if i < 7 else "BLOCKED",
            reason_code="POLICY_ALLOWED" if i < 7 else "POLICY_DENIED",
        )

    _insert_decision(
        tenant_id=tenant_id,
        decision_id=f"dec-{uuid.uuid4().hex[:10]}",
        created_at=now - timedelta(days=1, hours=1),
        release_status="BLOCKED",
        reason_code="OVERRIDE_EXPIRED",
    )
    _insert_decision(
        tenant_id=tenant_id,
        decision_id=f"dec-{uuid.uuid4().hex[:10]}",
        created_at=now - timedelta(days=1, hours=2),
        release_status="BLOCKED",
        reason_code="SOD_CONFLICT",
    )
    _insert_failed_override_sod_anomaly(tenant_id=tenant_id, created_at=now - timedelta(hours=12))

    for decision_id in decision_ids[:4]:
        _insert_override(
            tenant_id=tenant_id,
            decision_id=decision_id,
            actor="override-actor-1",
            created_at=now - timedelta(hours=3),
        )

    response = client.get(
        f"/tenants/{tenant_id}/governance-integrity",
        headers=jwt_headers(tenant_id=tenant_id, roles=["auditor"]),
        params={"window_days": 90},
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["tenant_id"] == tenant_id
    assert body["drift_index"] > 0
    assert body["override_abuse_score"] > 0
    assert body["governance_integrity_score"] < 100
    assert body["risk_level"] in {"STABLE", "WATCH", "CRITICAL"}
    assert body["separation_of_duties_violations"] >= 1

    drift = body["policy_drift"]
    assert drift["policy_count"] >= 1
    assert drift["policies"][0]["drift_score"] > 0
    assert "WEAKEN_APPROVAL_REQUIREMENT" in drift["signal_totals"]
    assert "OVERRIDE_TTL_INCREASE" in drift["signal_totals"]

    abuse = body["override_abuse"]
    assert abuse["repeat_actor_flag"] is True
    assert abuse["override_cluster_hotspot"] is not None


def test_governance_integrity_endpoint_is_tenant_scoped():
    _reset_db()
    tenant_a = "tenant-phase12-a"
    tenant_b = "tenant-phase12-b"

    response = client.get(
        f"/tenants/{tenant_b}/governance-integrity",
        headers=jwt_headers(tenant_id=tenant_a, roles=["auditor"]),
        params={"window_days": 90},
    )
    assert response.status_code == 403
    detail = response.json().get("detail") or {}
    assert detail.get("error_code") == "TENANT_SCOPE_FORBIDDEN"
