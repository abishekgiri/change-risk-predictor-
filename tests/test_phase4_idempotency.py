import concurrent.futures
import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from releasegate.audit.overrides import record_override, verify_override_chain
from releasegate.audit.recorder import AuditRecorder
from releasegate.config import DB_PATH
from releasegate.decision.types import Decision, EnforcementTargets
from releasegate.integrations.jira import routes as jira_routes
from releasegate.integrations.jira.types import TransitionCheckResponse
from releasegate.integrations.jira.workflow_gate import WorkflowGate
from releasegate.security.webhook_keys import create_webhook_key
from releasegate.server import app
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _record_decision(repo: str, pr_number: int, *, tenant_id: str = "tenant-test") -> Decision:
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="ALLOWED: phase4 idempotency test",
        policy_bundle_hash="phase4-hash",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="phase4-user",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={"signal_map": {"repo": repo, "pr_number": pr_number, "diff": {}}, "policies_requested": []},
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["PHASE4-1"]},
        ),
        tenant_id=tenant_id,
    )
    return AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number, tenant_id=tenant_id)


def test_jira_transition_route_replays_idempotent_response(monkeypatch):
    app_local = FastAPI()
    app_local.include_router(jira_routes.router, prefix="/integrations/jira")
    local_client = TestClient(app_local)

    call_count = {"n": 0}

    def _fake_check(self, request):
        call_count["n"] += 1
        return TransitionCheckResponse(
            allow=True,
            reason="ALLOWED: replayed",
            decision_id="decision-fixed-1",
            status="ALLOWED",
            policy_hash="policy-fixed",
            tenant_id="tenant-test",
        )

    monkeypatch.setattr(jira_routes.WorkflowGate, "check_transition", _fake_check)

    payload = {
        "issue_key": "PHASE4-123",
        "transition_id": "31",
        "source_status": "Open",
        "target_status": "Done",
        "actor_account_id": "acct-1",
        "actor_email": "user@example.com",
        "environment": "PRODUCTION",
        "project_key": "PHASE4",
        "issue_type": "Story",
        "tenant_id": "tenant-test",
        "context_overrides": {},
    }
    secret = f"jira-idem-secret-{uuid.uuid4().hex}"
    key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="jira",
        created_by="test-suite",
        raw_secret=secret,
        deactivate_existing=True,
    )
    payload_text = json.dumps(payload)
    ts = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{uuid.uuid4().hex[:8]}"
    canonical = "\n".join([ts, nonce, "POST", "/integrations/jira/transition/check", payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "Idempotency-Key": f"idem-{uuid.uuid4().hex[:12]}",
        "X-Signature": signature,
        "X-Key-Id": key["key_id"],
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "Content-Type": "application/json",
    }
    r1 = local_client.post("/integrations/jira/transition/check", content=payload_text.encode("utf-8"), headers=headers)
    # Refresh nonce/signature for second delivery attempt with same idempotency key.
    ts2 = str(int(datetime.now(timezone.utc).timestamp()))
    nonce2 = f"nonce-{uuid.uuid4().hex[:8]}"
    canonical2 = "\n".join([ts2, nonce2, "POST", "/integrations/jira/transition/check", payload_text])
    signature2 = hmac.new(secret.encode("utf-8"), canonical2.encode("utf-8"), hashlib.sha256).hexdigest()
    headers2 = {**headers, "X-Timestamp": ts2, "X-Nonce": nonce2, "X-Signature": signature2}
    r2 = local_client.post("/integrations/jira/transition/check", content=payload_text.encode("utf-8"), headers=headers2)
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["decision_id"] == r2.json()["decision_id"] == "decision-fixed-1"
    assert call_count["n"] == 1


def test_manual_override_endpoint_is_idempotent_with_header_key():
    repo = f"phase4-override-{uuid.uuid4().hex[:8]}"
    stored = _record_decision(repo, 401)
    idem = f"idem-{uuid.uuid4().hex}"

    payload = {
        "repo": repo,
        "pr_number": 401,
        "issue_key": "PHASE4-401",
        "decision_id": stored.decision_id,
        "reason": "emergency override approved",
        "ttl_seconds": 3600,
        "target_type": "pr",
        "target_id": f"{repo}#401",
    }
    headers = {
        **jwt_headers(roles=["admin"], scopes=["override:write"]),
        "Idempotency-Key": idem,
    }
    first = client.post("/audit/overrides", json=payload, params={"tenant_id": "tenant-test"}, headers=headers)
    second = client.post("/audit/overrides", json=payload, params={"tenant_id": "tenant-test"}, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["override_id"] == second.json()["override_id"]

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COUNT(*) FROM audit_overrides
            WHERE tenant_id = ? AND idempotency_key = ?
            """,
            ("tenant-test", idem),
        )
        assert cur.fetchone()[0] == 1
        cur.execute(
            """
            SELECT status FROM idempotency_keys
            WHERE tenant_id = ? AND operation = ? AND idem_key = ?
            """,
            ("tenant-test", "manual_override_create", idem),
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "completed"
    finally:
        conn.close()


def test_manual_override_endpoint_rejects_missing_ttl():
    repo = f"phase4-override-no-ttl-{uuid.uuid4().hex[:8]}"
    stored = _record_decision(repo, 405)
    headers = {
        **jwt_headers(roles=["admin"], scopes=["override:write"]),
        "Idempotency-Key": f"idem-{uuid.uuid4().hex}",
    }
    payload = {
        "repo": repo,
        "pr_number": 405,
        "issue_key": "PHASE4-405",
        "decision_id": stored.decision_id,
        "reason": "emergency override approved by release governance",
        "target_type": "pr",
        "target_id": f"{repo}#405",
    }
    response = client.post("/audit/overrides", json=payload, params={"tenant_id": "tenant-test"}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"]["error_code"] == "OVERRIDE_TTL_REQUIRED"


def test_manual_override_endpoint_rejects_missing_justification():
    repo = f"phase4-override-no-justification-{uuid.uuid4().hex[:8]}"
    stored = _record_decision(repo, 407)
    headers = {
        **jwt_headers(roles=["admin"], scopes=["override:write"]),
        "Idempotency-Key": f"idem-{uuid.uuid4().hex}",
    }
    payload = {
        "repo": repo,
        "pr_number": 407,
        "issue_key": "PHASE4-407",
        "decision_id": stored.decision_id,
        "reason": "   ",
        "ttl_seconds": 900,
        "target_type": "pr",
        "target_id": f"{repo}#407",
    }
    response = client.post("/audit/overrides", json=payload, params={"tenant_id": "tenant-test"}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"]["error_code"] == "OVERRIDE_JUSTIFICATION_REQUIRED"


def test_manual_override_endpoint_requires_admin_role():
    repo = f"phase4-override-no-admin-{uuid.uuid4().hex[:8]}"
    stored = _record_decision(repo, 406)
    headers = {
        **jwt_headers(roles=["operator"], scopes=["override:write"]),
        "Idempotency-Key": f"idem-{uuid.uuid4().hex}",
    }
    payload = {
        "repo": repo,
        "pr_number": 406,
        "issue_key": "PHASE4-406",
        "decision_id": stored.decision_id,
        "reason": "emergency override approved by release governance",
        "ttl_seconds": 900,
        "target_type": "pr",
        "target_id": f"{repo}#406",
    }
    response = client.post("/audit/overrides", json=payload, params={"tenant_id": "tenant-test"}, headers=headers)
    assert response.status_code == 403


def test_parallel_override_recording_with_same_key_produces_single_row():
    repo = f"phase4-chain-{uuid.uuid4().hex[:8]}"
    idem = f"idem-chain-{uuid.uuid4().hex}"

    def _worker():
        return record_override(
            repo=repo,
            pr_number=402,
            issue_key="PHASE4-402",
            decision_id="phase4-decision",
            actor="phase4-user",
            reason="parallel override",
            idempotency_key=idem,
            tenant_id="tenant-test",
            target_type="pr",
            target_id=f"{repo}#402",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: _worker(), range(20)))

    override_ids = {row["override_id"] for row in results}
    assert len(override_ids) == 1

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COUNT(*) FROM audit_overrides
            WHERE tenant_id = ? AND idempotency_key = ?
            """,
            ("tenant-test", idem),
        )
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()

    chain = verify_override_chain(repo=repo, pr=402, tenant_id="tenant-test")
    assert chain["valid"] is True


def test_proof_pack_json_is_deterministic_and_idempotent():
    repo = f"phase4-proof-{uuid.uuid4().hex[:8]}"
    stored = _record_decision(repo, 403)

    headers = jwt_headers(roles=["auditor"], scopes=["proofpack:read", "checkpoint:read", "policy:read"])
    params = {"format": "json", "tenant_id": "tenant-test"}
    first = client.get(f"/audit/proof-pack/{stored.decision_id}", params=params, headers=headers)
    second = client.get(f"/audit/proof-pack/{stored.decision_id}", params=params, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["proof_pack_id"] == second.json()["proof_pack_id"]
    assert first.json()["export_checksum"] == second.json()["export_checksum"]

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COUNT(*) FROM audit_proof_packs
            WHERE tenant_id = ? AND decision_id = ? AND output_format = 'json'
            """,
            ("tenant-test", stored.decision_id),
        )
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()


def test_parallel_jira_transition_evaluation_has_single_decision_record():
    gate = WorkflowGate()
    gate.client.get_issue_property = lambda issue_key, name=None: {}

    request_payload = {
        "issue_key": "PHASE4-TRANS-1",
        "transition_id": "31",
        "source_status": "Open",
        "target_status": "Done",
        "actor_account_id": "acct-2",
        "actor_email": "user2@example.com",
        "environment": "PRODUCTION",
        "project_key": "PHASE4",
        "issue_type": "Story",
        "tenant_id": "tenant-test",
        "context_overrides": {"idempotency_key": f"transition-{uuid.uuid4().hex}"},
    }

    from releasegate.integrations.jira.types import TransitionCheckRequest

    template = TransitionCheckRequest(**request_payload)
    base_eval_key = gate._compute_key(template, tenant_id="tenant-test")
    expected_eval_key = f"{base_eval_key}:missing-risk"

    def _worker():
        req = TransitionCheckRequest(**request_payload)
        return gate.check_transition(req)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: _worker(), range(20)))

    decision_ids = {r.decision_id for r in results}
    assert len(decision_ids) == 1

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COUNT(*) FROM audit_decisions
            WHERE tenant_id = ? AND evaluation_key = ?
            """,
            ("tenant-test", expected_eval_key),
        )
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()


def test_decision_hash_fields_are_stored():
    repo = f"phase4-hashes-{uuid.uuid4().hex[:8]}"
    stored = _record_decision(repo, 404)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT decision_hash, input_hash, policy_hash, replay_hash
            FROM audit_decisions
            WHERE tenant_id = ? AND decision_id = ?
            """,
            ("tenant-test", stored.decision_id),
        ).fetchone()
        assert row is not None
        assert row["decision_hash"]
        assert row["input_hash"]
        assert row["policy_hash"]
        assert row["replay_hash"]
    finally:
        conn.close()
