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


def _table_count(table_name: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def _seed_historical_decision(
    *,
    tenant_id: str,
    decision_id: str,
    transition_id: str,
    target_status: str,
    release_status: str,
    created_at: datetime,
    policy_hash: str = "sha256:seed-policy",
) -> None:
    payload = {
        "release_status": release_status,
        "reason_code": "POLICY_ALLOWED" if release_status == "ALLOWED" else "POLICY_DENIED",
        "input_snapshot": {
            "request": {
                "issue_key": f"{tenant_id}-ISSUE",
                "transition_id": transition_id,
                "actor_account_id": f"{tenant_id}-actor",
                "source_status": "In Progress",
                "target_status": target_status,
                "environment": "prod",
                "project_key": "PROJ",
                "context_overrides": {"workflow_id": "wf-release"},
            },
            "signal_map": {"risk": {"score": 0.85}},
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
                release_status,
                "bundle-1",
                "engine-v1",
                f"decision-{decision_id}",
                f"input-{decision_id}",
                policy_hash,
                f"replay-{decision_id}",
                json.dumps(payload, separators=(",", ":"), sort_keys=True),
                created_at.isoformat(),
                f"eval-{decision_id}",
            ),
        )
        conn.commit()
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

    stage_resp = client.post(
        f"/policies/{created['policy_id']}/stage",
        headers=headers,
        json={"tenant_id": "tenant-registry-api"},
    )
    assert stage_resp.status_code == 200, stage_resp.text
    staged = stage_resp.json()
    assert staged["status"] == "STAGED"

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
    assert "component_lineage" in simulated
    assert simulated["resolution_conflicts"] == []


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

    stage_resp = client.post(
        f"/policies/{created['policy_id']}/stage",
        headers=headers,
        json={"tenant_id": "tenant-registry-api"},
    )
    assert stage_resp.status_code == 200, stage_resp.text

    activate_resp = client.post(
        f"/policies/{created['policy_id']}/activate",
        headers=headers,
        json={"tenant_id": "tenant-registry-api"},
    )
    assert activate_resp.status_code == 400
    assert "lint errors" in activate_resp.text.lower()


def test_policy_registry_api_rejects_monotonic_weakening_on_create():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api")

    org = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "org",
            "scope_id": "tenant-registry-api",
            "status": "ACTIVE",
            "policy_json": {
                "strict_fail_closed": True,
                "required_approvals": 2,
                "approval_requirements": {
                    "min_approvals": 2,
                    "required_roles": ["security"],
                    "role_capacity": {"security": 2},
                },
            },
        },
    )
    assert org.status_code == 200, org.text

    weak = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "project",
            "scope_id": "PROJ",
            "status": "DRAFT",
            "policy_json": {
                "strict_fail_closed": False,
                "required_approvals": 1,
                "approval_requirements": {"min_approvals": 1, "required_roles": []},
            },
        },
    )
    assert weak.status_code == 400
    detail = weak.json().get("detail") or {}
    assert detail.get("error_code") == "POLICY_MONOTONICITY_VIOLATION"
    assert detail.get("stage") == "create"


def test_policy_registry_api_rejects_monotonic_weakening_on_activate():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api")

    weak_draft = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "project",
            "scope_id": "PROJ",
            "status": "DRAFT",
            "policy_json": {
                "strict_fail_closed": False,
                "required_approvals": 1,
            },
        },
    )
    assert weak_draft.status_code == 200, weak_draft.text
    weak_policy_id = weak_draft.json()["policy_id"]
    stage = client.post(
        f"/policies/{weak_policy_id}/stage",
        headers=headers,
        json={"tenant_id": "tenant-registry-api"},
    )
    assert stage.status_code == 200, stage.text

    org = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "org",
            "scope_id": "tenant-registry-api",
            "status": "ACTIVE",
            "policy_json": {
                "strict_fail_closed": True,
                "required_approvals": 2,
                "approval_requirements": {
                    "min_approvals": 2,
                    "required_roles": ["security"],
                    "role_capacity": {"security": 2},
                },
            },
        },
    )
    assert org.status_code == 200, org.text

    activate = client.post(
        f"/policies/{weak_policy_id}/activate",
        headers=headers,
        json={"tenant_id": "tenant-registry-api"},
    )
    assert activate.status_code == 400
    detail = activate.json().get("detail") or {}
    assert detail.get("error_code") == "POLICY_MONOTONICITY_VIOLATION"
    assert detail.get("stage") == "activate"


def test_policy_registry_api_rollback_restores_previous_active():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api")

    first = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "51",
            "status": "ACTIVE",
            "policy_json": {"required_approvals": 1, "transition_rules": [{"transition_id": "51", "result": "ALLOW"}]},
        },
    )
    assert first.status_code == 200, first.text

    second = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "51",
            "status": "ACTIVE",
            "policy_json": {"required_approvals": 2, "transition_rules": [{"transition_id": "51", "result": "BLOCK"}]},
        },
    )
    assert second.status_code == 200, second.text
    second_policy_id = second.json()["policy_id"]

    rollback = client.post(
        f"/policies/{second_policy_id}/rollback",
        headers=headers,
        json={"tenant_id": "tenant-registry-api"},
    )
    assert rollback.status_code == 200, rollback.text
    restored = rollback.json()
    assert restored["policy_id"] == first.json()["policy_id"]
    assert restored["status"] == "ACTIVE"

    events = client.get(
        f"/policies/{second_policy_id}/events",
        headers=headers,
        params={"tenant_id": "tenant-registry-api"},
    )
    assert events.status_code == 200, events.text
    event_types = {event.get("event_type") for event in events.json().get("events", [])}
    assert "POLICY_CREATED" in event_types
    assert "POLICY_ACTIVATED" in event_types
    assert "POLICY_ARCHIVED" in event_types
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


def test_policy_registry_api_simulate_decision_status_filter_supports_staged_shadow():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api")

    active = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "61",
            "status": "ACTIVE",
            "policy_json": {"transition_rules": [{"transition_id": "61", "result": "ALLOW"}]},
        },
    )
    assert active.status_code == 200, active.text

    staged = client.post(
        "/policies",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "61",
            "status": "STAGED",
            "policy_json": {"transition_rules": [{"transition_id": "61", "result": "BLOCK"}]},
        },
    )
    assert staged.status_code == 200, staged.text
    assert staged.json()["status"] == "STAGED"

    active_sim = client.post(
        "/simulate-decision",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "issue_key": "RG-61",
            "transition_id": "61",
            "project_id": "PROJ",
            "workflow_id": "wf-release",
            "environment": "prod",
            "status_filter": "ACTIVE",
            "context": {"org_id": "tenant-registry-api"},
        },
    )
    assert active_sim.status_code == 200, active_sim.text
    assert active_sim.json()["status"] == "ALLOWED"

    staged_sim = client.post(
        "/simulate-decision",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "issue_key": "RG-61",
            "transition_id": "61",
            "project_id": "PROJ",
            "workflow_id": "wf-release",
            "environment": "prod",
            "status_filter": "STAGED",
            "context": {"org_id": "tenant-registry-api"},
        },
    )
    assert staged_sim.status_code == 200, staged_sim.text
    assert staged_sim.json()["status"] == "BLOCKED"


def test_policies_simulate_endpoint_writes_simulation_audit_only():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api", roles=["admin", "operator"], scopes=["policy:read"])

    create_resp = client.post(
        "/policies",
        headers=jwt_headers(tenant_id="tenant-registry-api"),
        json={
            "tenant_id": "tenant-registry-api",
            "scope_type": "transition",
            "scope_id": "71",
            "status": "ACTIVE",
            "policy_json": {
                "strict_fail_closed": True,
                "transition_rules": [{"transition_id": "71", "result": "ALLOW"}],
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text

    before_decisions = _table_count("audit_decisions")
    before_idempotency = _table_count("idempotency_keys")
    before_security = _table_count("security_audit_events")
    before_sim = _table_count("policy_simulation_events")

    resp = client.post(
        "/policies/simulate",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "issue_key": "RG-71",
            "transition_id": "71",
            "project_id": "PROJ",
            "workflow_id": "wf-release",
            "environment": "prod",
            "context": {"org_id": "tenant-registry-api"},
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["enforced"] is False
    assert payload["trace_id"]
    assert _table_count("policy_simulation_events") == before_sim + 1
    assert _table_count("audit_decisions") == before_decisions
    assert _table_count("idempotency_keys") == before_idempotency
    assert _table_count("security_audit_events") == before_security + 1


def test_policy_conflict_analysis_endpoint_reports_contradictions():
    _reset_db()
    headers = jwt_headers(tenant_id="tenant-registry-api", roles=["admin", "operator"], scopes=["policy:read"])

    resp = client.post(
        "/policies/conflicts/analyze",
        headers=headers,
        json={
            "tenant_id": "tenant-registry-api",
            "policy_json": {
                "strict_fail_closed": True,
                "required_transitions": ["99"],
                "transition_rules": [
                    {"transition_id": "99", "result": "ALLOW", "priority": 100},
                    {"transition_id": "99", "result": "BLOCK", "priority": 100},
                ],
            },
        },
    )
    assert resp.status_code == 200, resp.text
    analysis = resp.json()["analysis"]
    assert analysis["summary"]["contradiction_count"] >= 1
    assert analysis["ok"] is False


def test_policy_simulate_historical_endpoint_returns_impact_summary():
    _reset_db()
    tenant_id = "tenant-registry-api"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin", "operator"], scopes=["policy:read"])
    now = datetime.now(timezone.utc)

    _seed_historical_decision(
        tenant_id=tenant_id,
        decision_id=f"dec-{uuid.uuid4()}",
        transition_id="31",
        target_status="Done",
        release_status="ALLOWED",
        created_at=now - timedelta(days=2),
    )
    _seed_historical_decision(
        tenant_id=tenant_id,
        decision_id=f"dec-{uuid.uuid4()}",
        transition_id="31",
        target_status="Done",
        release_status="ALLOWED",
        created_at=now - timedelta(days=3),
    )
    _seed_historical_decision(
        tenant_id=tenant_id,
        decision_id=f"dec-{uuid.uuid4()}",
        transition_id="31",
        target_status="Done",
        release_status="BLOCKED",
        created_at=now - timedelta(days=5),
    )

    resp = client.post(
        "/policies/simulate-historical",
        headers=headers,
        json={
            "tenant_id": tenant_id,
            "time_window_days": 30,
            "policy_json": {
                "strict_fail_closed": True,
                "transition_rules": [
                    {
                        "transition_id": "31",
                        "environment": "prod",
                        "result": "BLOCK",
                        "priority": 100,
                    }
                ],
            },
            "transition_id": "31",
            "project_key": "PROJ",
            "workflow_id": "wf-release",
            "environment": "prod",
            "only_protected": True,
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["enforced"] is False
    assert payload["time_window_days"] == 30
    assert payload["simulated_events"] == 3
    assert payload["would_block_count"] == 2
    assert payload["would_allow_count"] == 0
    assert payload["override_delta"] == 2
    assert payload["delta_breakdown"]["allow_to_deny"] == 2
    assert payload["skipped_ratio"] == 0.0
    assert payload["missing_context_ratio"] == 0.0
    assert payload["impacted_workflows"][0]["transition_id"] == "31"
    assert payload["high_risk_clusters"][0]["count"] == 2


def test_policy_diff_impact_endpoint_reports_weakening_changes():
    _reset_db()
    tenant_id = "tenant-registry-api"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin", "operator"], scopes=["policy:read"])

    current_policy = {
        "strict_fail_closed": True,
        "approval_requirements": {"min_approvals": 2, "required_roles": ["security", "em"]},
        "protected_statuses": ["Done", "Released"],
        "transition_rules": [
            {"rule_id": "prod-block", "transition_id": "31", "environment": "prod", "result": "BLOCK", "priority": 100}
        ],
        "risk_thresholds": {"prod": {"max_score": 0.7}},
    }
    candidate_policy = {
        "strict_fail_closed": False,
        "approval_requirements": {"min_approvals": 1, "required_roles": ["security"]},
        "protected_statuses": ["Released"],
        "transition_rules": [
            {"rule_id": "prod-block", "transition_id": "31", "environment": "prod", "result": "ALLOW", "priority": 100}
        ],
        "risk_thresholds": {"prod": {"max_score": 0.85}},
    }

    resp = client.post(
        "/policies/diff-impact",
        headers=headers,
        json={
            "tenant_id": tenant_id,
            "current_policy_json": current_policy,
            "candidate_policy_json": candidate_policy,
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["overall"] == "WEAKENING"
    warning_codes = {str(item.get("code")) for item in payload["warnings"]}
    assert "WEAKEN_STRICT_FAIL_CLOSED" in warning_codes
    assert "WEAKEN_APPROVAL_REQUIREMENT" in warning_codes
    assert "WEAKEN_PROTECTED_STATUSES" in warning_codes
    assert "WEAKEN_RISK_THRESHOLD" in warning_codes
    assert "WEAKEN_RULE_RESULT" in warning_codes


def test_policy_diff_impact_missing_candidate_risk_threshold_is_weakening():
    _reset_db()
    tenant_id = "tenant-registry-api"
    headers = jwt_headers(tenant_id=tenant_id, roles=["admin", "operator"], scopes=["policy:read"])

    resp = client.post(
        "/policies/diff-impact",
        headers=headers,
        json={
            "tenant_id": tenant_id,
            "current_policy_json": {
                "risk_thresholds": {
                    "prod": {
                        "max_score": 0.7,
                    }
                }
            },
            "candidate_policy_json": {
                "risk_thresholds": {},
            },
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["overall"] == "WEAKENING"
    warning_codes = {str(item.get("code")) for item in payload["warnings"]}
    assert "WEAKEN_RISK_THRESHOLD" in warning_codes
    threshold_changes = payload["strictness_delta"]["risk_threshold_changes"]
    assert threshold_changes
    assert threshold_changes[0]["comparison_mode"] == "missing_default"
    assert threshold_changes[0]["from"] == 0.7
    assert threshold_changes[0]["to"] is None
