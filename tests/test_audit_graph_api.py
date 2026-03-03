from __future__ import annotations

import json
import os
import sqlite3
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


def _seed_graph_fixture(tenant_id: str, decision_id: str) -> None:
    now = datetime.now(timezone.utc)
    payload = {
        "decision_id": decision_id,
        "release_status": "ALLOWED",
        "policy_bindings": [
            {
                "policy_id": "RG-POLICY-1",
                "policy_version": "3",
                "policy_hash": "sha256:policy-1",
            }
        ],
        "input_snapshot": {
            "request": {
                "issue_key": "RG-401",
                "transition_id": "31",
                "actor_account_id": "acct-graph",
                "source_status": "In Progress",
                "target_status": "Done",
                "environment": "prod",
                "project_key": "RG",
                "context_overrides": {"workflow_id": "wf-release"},
            },
            "risk_meta": {
                "risk_score": 0.83,
                "risk_level": "HIGH",
                "signal_source": "risk-engine",
                "computed_at": now.isoformat(),
            },
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
                "ctx-graph",
                "org/repo",
                7,
                "ALLOWED",
                "bundle",
                "engine-v1",
                "decision-hash",
                "input-hash",
                "policy-hash",
                "replay-hash",
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                now.isoformat(),
                "eval-graph",
            ),
        )
        conn.execute(
            """
            INSERT INTO decision_transition_links (
                tenant_id, decision_id, jira_issue_id, transition_id, actor,
                source_status, target_status, policy_id, policy_version, policy_hash,
                context_hash, expires_at, consumed, consumed_at, consumed_by_request_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                decision_id,
                "RG-401",
                "31",
                "acct-graph",
                "In Progress",
                "Done",
                "RG-POLICY-1",
                3,
                "sha256:policy-1",
                "ctx-hash",
                (now + timedelta(hours=1)).isoformat(),
                0,
                None,
                None,
                now.isoformat(),
            ),
        )
        conn.execute(
            """
            INSERT INTO decision_approvals (
                tenant_id, approval_id, decision_id, approval_scope_hash, approval_scope_json,
                approval_group, approver_actor, approver_role, justification_json,
                justification_hash, request_id, created_at, revoked_at, revoked_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                "app-1",
                decision_id,
                "scope-hash",
                json.dumps({"scope": "release"}, separators=(",", ":"), sort_keys=True),
                "CAB",
                "acct-security",
                "security",
                json.dumps({"reason": "approved"}, separators=(",", ":"), sort_keys=True),
                "just-hash",
                "req-1",
                now.isoformat(),
                None,
                None,
            ),
        )
        conn.execute(
            """
            INSERT INTO audit_overrides (
                tenant_id, override_id, decision_id, repo, pr_number, issue_key, actor,
                reason, target_type, target_id, idempotency_key, previous_hash, event_hash,
                ttl_seconds, expires_at, requested_by, approved_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                "ovr-1",
                decision_id,
                "org/repo",
                7,
                "RG-401",
                "acct-ops",
                "emergency override",
                "issue",
                "RG-401",
                "idem-ovr-1",
                "",
                "event-hash-ovr-1",
                3600,
                (now + timedelta(hours=1)).isoformat(),
                "acct-ops",
                "acct-admin",
                now.isoformat(),
            ),
        )
        conn.execute(
            """
            INSERT INTO signal_attestations (
                tenant_id, signal_id, signal_type, signal_source, subject_type, subject_id,
                computed_at, expires_at, payload_json, signal_hash, sig_alg, signature, key_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                "sig-1",
                "risk_eval",
                "risk-engine",
                "jira_issue",
                "RG-401",
                now.isoformat(),
                (now + timedelta(hours=24)).isoformat(),
                json.dumps({"risk_score": 0.83}, separators=(",", ":"), sort_keys=True),
                "sha256:sig",
                None,
                None,
                None,
                now.isoformat(),
            ),
        )
        conn.execute(
            """
            INSERT INTO deployment_decision_links (
                tenant_id, deployment_event_id, decision_id, jira_issue_id, correlation_id,
                environment, service, artifact_digest, risk_eval_id, risk_evaluated_at,
                override_state_at_deploy, override_id, deployed_at, source,
                contract_mode, contract_verdict, violation_codes_json, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                "dep-1",
                decision_id,
                "RG-401",
                "corr-1",
                "prod",
                "billing",
                "sha256:artifact",
                "sig-1",
                now.isoformat(),
                "NONE",
                None,
                now.isoformat(),
                "github-actions",
                "STRICT",
                "ALLOW",
                "[]",
                "ok",
                now.isoformat(),
            ),
        )
        conn.execute(
            """
            INSERT INTO audit_independent_daily_checkpoints (
                tenant_id, checkpoint_id, date_utc, as_of_utc, ledger_root, ledger_size,
                prev_checkpoint_hash, checkpoint_hash, signature_algorithm, signature_value,
                signing_key_id, anchor_provider, anchor_ref, anchor_receipt_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                "cp-2026-03-10",
                now.date().isoformat(),
                now.isoformat(),
                "root-hash",
                1,
                "",
                "checkpoint-hash",
                "ed25519",
                "sig",
                "key-1",
                "http_transparency",
                "external-ref",
                json.dumps({}, separators=(",", ":"), sort_keys=True),
                now.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_governance_decision_graph_returns_trace_nodes_and_edges():
    _reset_db()
    tenant_id = "tenant-graph"
    decision_id = "decision-graph-1"
    _seed_graph_fixture(tenant_id, decision_id)

    resp = client.get(
        f"/governance/decisions/{decision_id}/graph",
        params={"tenant_id": tenant_id},
        headers=jwt_headers(tenant_id=tenant_id, scopes=["policy:read"]),
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    node_types = {node["type"] for node in payload["nodes"]}
    edge_types = {edge["type"] for edge in payload["edges"]}

    assert "decision" in node_types
    assert "policy_snapshot" in node_types
    assert "approval" in node_types
    assert "override" in node_types
    assert "signal_attestation" in node_types
    assert "deployment" in node_types
    assert "independent_checkpoint" in node_types

    assert "bound_to" in edge_types
    assert "approved_by" in edge_types
    assert "overridden_by" in edge_types
    assert "evaluated_with" in edge_types
    assert "authorized_by" in edge_types
    assert "anchored_in" in edge_types
