from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from releasegate.audit.recorder import AuditRecorder
from releasegate.config import DB_PATH
from releasegate.decision.types import Decision, DecisionType, EnforcementTargets, ExternalKeys, PolicyBinding
from releasegate.integrations.jira.approvals_orchestration import (
    build_approval_scope_payload,
    compute_approval_scope_hash,
    create_decision_approval,
    evaluate_cab_groups,
    list_active_scope_approvals,
    normalize_approval_justification,
)
from releasegate.security.webhook_keys import create_webhook_key
from releasegate.server import app
from releasegate.storage.schema import init_db


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _seed_decision_with_scope(
    *,
    tenant_id: str,
    decision_id: str,
    scope_payload: dict,
    effective_policy: dict | None = None,
) -> str:
    scope_hash = compute_approval_scope_hash(scope_payload)
    decision = Decision(
        decision_id=decision_id,
        tenant_id=tenant_id,
        timestamp=datetime.now(timezone.utc),
        release_status=DecisionType.CONDITIONAL,
        context_id=f"jira:{tenant_id}:RG-20:31",
        actor_id="submitter-1",
        policy_bundle_hash="bundle-15",
        policy_bindings=[
            PolicyBinding(
                policy_id="policy.release.prod",
                policy_version="15",
                policy_hash="policy-hash-15",
                tenant_id=tenant_id,
                policy={"id": "policy.release.prod", "version": "15"},
            )
        ],
        enforcement_targets=EnforcementTargets(
            repository="org/repo",
            pr_number=20,
            ref="abc123",
            external=ExternalKeys(jira=["RG-20"]),
        ),
        input_snapshot={
            "approval_scope": {
                "hash": scope_hash,
                "payload": scope_payload,
            },
            "registry_policy": {
                "effective_policy": effective_policy or {},
            },
        },
        message="CONDITIONAL: approvals required",
    )
    AuditRecorder.record_with_context(decision, repo="org/repo", pr_number=20, tenant_id=tenant_id)
    return scope_hash


def test_approval_scope_hash_changes_on_risk_policy_and_commit_change():
    base = build_approval_scope_payload(
        tenant_id="tenant-a",
        issue_key="RG-20",
        transition_id="31",
        source_status="In Progress",
        target_status="Done",
        environment="PRODUCTION",
        project_key="RG",
        policy_hash="policy-a",
        actor_account_id="submitter-1",
        commit_sha="abc123",
        artifact_digest="sha256:aaa",
        risk_level="MEDIUM",
        risk_score=65,
        risk_reason_codes=["BASELINE"],
    )
    changed_risk = dict(base)
    changed_risk["risk_summary"] = {"risk_level": "HIGH", "risk_score": 90.0, "risk_reason_codes": ["BASELINE"]}
    changed_policy = dict(base)
    changed_policy["policy_hash"] = "policy-b"
    changed_commit = dict(base)
    changed_commit["commit_sha"] = "def456"

    h_base = compute_approval_scope_hash(base)
    assert h_base != compute_approval_scope_hash(changed_risk)
    assert h_base != compute_approval_scope_hash(changed_policy)
    assert h_base != compute_approval_scope_hash(changed_commit)


def test_create_decision_approval_enforces_structured_justification():
    _reset_db()
    tenant_id = "tenant-approval-justification"
    scope_payload = build_approval_scope_payload(
        tenant_id=tenant_id,
        issue_key="RG-20",
        transition_id="31",
        source_status="In Progress",
        target_status="Done",
        environment="PRODUCTION",
        project_key="RG",
        policy_hash="policy-hash-15",
        actor_account_id="submitter-1",
        commit_sha="abc123",
        artifact_digest="sha256:aaa",
        risk_level="HIGH",
        risk_score=85,
    )
    _seed_decision_with_scope(
        tenant_id=tenant_id,
        decision_id="decision-approval-1",
        scope_payload=scope_payload,
        effective_policy={
            "approval_requirements": {
                "justification": {"reason_required": True, "reason_min_length": 24, "required_fields": ["impact"]}
            }
        },
    )

    with pytest.raises(ValueError, match="JUSTIFICATION_TOO_SHORT"):
        create_decision_approval(
            tenant_id=tenant_id,
            decision_id="decision-approval-1",
            approver_actor="security-1",
            approver_role="security",
            approval_group="cab",
            justification={"reason": "too short", "impact": "low"},
            request_id="req-short",
        )

    created = create_decision_approval(
        tenant_id=tenant_id,
        decision_id="decision-approval-1",
        approver_actor="security-1",
        approver_role="security",
        approval_group="cab",
        justification={
            "reason": "Emergency fix reviewed with rollback and blast-radius analysis.",
            "impact": "low",
            "risk_acknowledgement": True,
            "references": ["INC-123"],
        },
        request_id="req-valid",
    )
    assert created["decision_id"] == "decision-approval-1"
    assert created["approver_actor"] == "security-1"
    assert created["approval_scope_hash"] == compute_approval_scope_hash(scope_payload)


def test_scope_invalidation_excludes_prior_scope_approvals():
    _reset_db()
    tenant_id = "tenant-approval-invalidation"
    scope_a = build_approval_scope_payload(
        tenant_id=tenant_id,
        issue_key="RG-20",
        transition_id="31",
        source_status="In Progress",
        target_status="Done",
        environment="PRODUCTION",
        project_key="RG",
        policy_hash="policy-hash-15",
        actor_account_id="submitter-1",
        commit_sha="abc123",
        artifact_digest="sha256:aaa",
        risk_level="MEDIUM",
        risk_score=60,
    )
    scope_b = build_approval_scope_payload(
        tenant_id=tenant_id,
        issue_key="RG-20",
        transition_id="31",
        source_status="In Progress",
        target_status="Done",
        environment="PRODUCTION",
        project_key="RG",
        policy_hash="policy-hash-15",
        actor_account_id="submitter-1",
        commit_sha="abc123",
        artifact_digest="sha256:aaa",
        risk_level="HIGH",
        risk_score=92,
    )
    hash_a = _seed_decision_with_scope(
        tenant_id=tenant_id,
        decision_id="decision-scope-a",
        scope_payload=scope_a,
    )
    _seed_decision_with_scope(
        tenant_id=tenant_id,
        decision_id="decision-scope-b",
        scope_payload=scope_b,
    )

    create_decision_approval(
        tenant_id=tenant_id,
        decision_id="decision-scope-a",
        approver_actor="ops-1",
        approver_role="ops",
        approval_group="cab",
        justification={"reason": "Risk accepted by operations after staged validation completes."},
        request_id="req-a",
    )
    approvals_a = list_active_scope_approvals(tenant_id=tenant_id, approval_scope_hash=hash_a)
    approvals_b = list_active_scope_approvals(
        tenant_id=tenant_id,
        approval_scope_hash=compute_approval_scope_hash(scope_b),
    )
    assert len(approvals_a) == 1
    assert approvals_b == []


def test_cab_group_evaluation_enforces_unique_roles_and_submitter_exclusion():
    groups = [
        {
            "name": "cab",
            "min_approvals": 2,
            "min_unique_roles": 2,
            "allowed_roles": ["security", "ops", "em"],
            "forbid_same_actor_as_submitter": True,
        }
    ]
    failing = evaluate_cab_groups(
        groups=groups,
        approvals=[
            {"approval_group": "cab", "approver_actor": "submitter-1", "approver_role": "security"},
            {"approval_group": "cab", "approver_actor": "sec-2", "approver_role": "security"},
            {"approval_group": "cab", "approver_actor": "sec-3", "approver_role": "security"},
        ],
        submitter_actor="submitter-1",
    )
    assert failing["required"] is True
    assert failing["satisfied"] is False
    assert failing["missing_requirements"]

    passing = evaluate_cab_groups(
        groups=groups,
        approvals=[
            {"approval_group": "cab", "approver_actor": "sec-2", "approver_role": "security"},
            {"approval_group": "cab", "approver_actor": "ops-2", "approver_role": "ops"},
        ],
        submitter_actor="submitter-1",
    )
    assert passing["required"] is True
    assert passing["satisfied"] is True
    assert passing["missing_requirements"] == []


def test_normalize_approval_justification_trims_and_validates():
    payload = normalize_approval_justification(
        {
            "reason": "  Long enough reason for change approval and risk acknowledgement.  ",
            "risk_acknowledgement": True,
            "impact": " medium ",
            "references": [" INC-1 ", "INC-1", " RUNBOOK-2 "],
        },
        reason_required=True,
        reason_min_length=24,
        required_fields=["impact"],
    )
    assert payload["reason"].startswith("Long enough reason")
    assert payload["impact"] == "medium"
    assert payload["references"] == ["INC-1", "RUNBOOK-2"]


def _signed_headers(*, tenant_id: str, path: str, payload_text: str) -> dict:
    secret = f"approval-scope-secret-{tenant_id}"
    key = create_webhook_key(
        tenant_id=tenant_id,
        integration_id="jira",
        created_by="tests",
        raw_secret=secret,
        deactivate_existing=True,
    )
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-{uuid.uuid4().hex[:12]}"
    canonical = "\n".join([timestamp, nonce, "POST", path, payload_text])
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Key-Id": key["key_id"],
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "Idempotency-Key": f"idem-{uuid.uuid4().hex[:16]}",
    }


def _post_approval(*, tenant_id: str, decision_id: str, payload: dict):
    path = f"/integrations/jira/decisions/{decision_id}/approvals"
    payload_text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return client.post(
        path,
        content=payload_text.encode("utf-8"),
        headers=_signed_headers(tenant_id=tenant_id, path=path, payload_text=payload_text),
    )


def test_decision_approval_endpoint_rejects_short_reason():
    _reset_db()
    tenant_id = "tenant-approval-api-short"
    scope_payload = build_approval_scope_payload(
        tenant_id=tenant_id,
        issue_key="RG-21",
        transition_id="31",
        source_status="In Progress",
        target_status="Done",
        environment="PRODUCTION",
        project_key="RG",
        policy_hash="policy-hash-15",
        actor_account_id="submitter-1",
        risk_level="HIGH",
        risk_score=88,
    )
    _seed_decision_with_scope(
        tenant_id=tenant_id,
        decision_id="decision-api-short",
        scope_payload=scope_payload,
        effective_policy={
            "approval_requirements": {
                "justification": {"reason_required": True, "reason_min_length": 20}
            }
        },
    )
    response = _post_approval(
        tenant_id=tenant_id,
        decision_id="decision-api-short",
        payload={
            "tenant_id": tenant_id,
            "approval_group": "cab",
            "approver_role": "security",
            "justification": {"reason": "short"},
            "request_id": "approval-short-1",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error_code"] == "JUSTIFICATION_TOO_SHORT"


def test_decision_approval_endpoint_accepts_valid_and_is_idempotent():
    _reset_db()
    tenant_id = "tenant-approval-api-valid"
    scope_payload = build_approval_scope_payload(
        tenant_id=tenant_id,
        issue_key="RG-22",
        transition_id="31",
        source_status="In Progress",
        target_status="Done",
        environment="PRODUCTION",
        project_key="RG",
        policy_hash="policy-hash-15",
        actor_account_id="submitter-1",
        risk_level="HIGH",
        risk_score=91,
    )
    _seed_decision_with_scope(
        tenant_id=tenant_id,
        decision_id="decision-api-valid",
        scope_payload=scope_payload,
    )

    payload = {
        "tenant_id": tenant_id,
        "approval_group": "cab",
        "approver_role": "security",
        "justification": {
            "reason": "Approval granted after CAB review and documented rollback verification.",
            "impact": "low",
        },
        "request_id": "approval-valid-1",
    }
    first = _post_approval(tenant_id=tenant_id, decision_id="decision-api-valid", payload=payload)
    second = _post_approval(tenant_id=tenant_id, decision_id="decision-api-valid", payload=payload)
    assert first.status_code == 200
    assert second.status_code == 200
    first_body = first.json()
    second_body = second.json()
    assert first_body["ok"] is True
    assert first_body["approval_id"] == second_body["approval_id"]
    assert first_body["approval_scope_hash"] == compute_approval_scope_hash(scope_payload)
