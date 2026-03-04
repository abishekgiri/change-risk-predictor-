from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import zipfile
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


def _seed_export_fixture(tenant_id: str) -> None:
    created_at = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
    decision_payload = {
        "decision_id": "d-export-1",
        "release_status": "ALLOWED",
        "policy_bindings": [{"policy_id": "SEC-1", "policy_version": "1", "policy_hash": "sha256:p1"}],
        "input_snapshot": {
            "request": {
                "issue_key": "RG-701",
                "transition_id": "31",
                "actor_account_id": "acct-export",
                "source_status": "In Progress",
                "target_status": "Done",
                "environment": "prod",
                "project_key": "RG",
                "context_overrides": {"workflow_id": "wf-release"},
            },
            "risk_meta": {"risk_score": 0.77, "risk_level": "HIGH"},
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
                "d-export-1",
                "ctx-export-1",
                "org/repo",
                10,
                "ALLOWED",
                "bundle",
                "engine-v1",
                "decision-hash",
                "input-hash",
                "policy-hash",
                "replay-hash",
                json.dumps(decision_payload, sort_keys=True, separators=(",", ":")),
                created_at.isoformat(),
                "eval-export-1",
            ),
        )
        conn.execute(
            """
            INSERT INTO policy_registry_entries (
                tenant_id, policy_id, scope_type, scope_id, version, status, policy_json,
                policy_hash, lint_errors_json, lint_warnings_json, rollout_percentage,
                rollout_scope, created_at, created_by, activated_at, activated_by,
                supersedes_policy_id, archived_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                "SEC-1",
                "transition",
                "31",
                1,
                "ACTIVE",
                json.dumps({"transition_rules": [{"transition_id": "31", "result": "ALLOW"}]}, separators=(",", ":"), sort_keys=True),
                "sha256:p1",
                "[]",
                "[]",
                100,
                None,
                created_at.isoformat(),
                "acct-admin",
                created_at.isoformat(),
                "acct-admin",
                None,
                None,
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
                "app-export-1",
                "d-export-1",
                "scope-hash",
                json.dumps({"scope": "release"}, separators=(",", ":"), sort_keys=True),
                "CAB",
                "acct-security",
                "security",
                json.dumps({"reason": "approved"}, separators=(",", ":"), sort_keys=True),
                "just-hash",
                "req-export",
                created_at.isoformat(),
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
                "ovr-export-1",
                "d-export-1",
                "org/repo",
                10,
                "RG-701",
                "acct-ops",
                "override",
                "issue",
                "RG-701",
                "idem-export",
                "",
                "event-hash-export",
                3600,
                (created_at + timedelta(hours=1)).isoformat(),
                "acct-ops",
                "acct-admin",
                created_at.isoformat(),
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
                "sig-export-1",
                "risk_eval",
                "risk-engine",
                "jira_issue",
                "RG-701",
                created_at.isoformat(),
                (created_at + timedelta(hours=24)).isoformat(),
                json.dumps({"risk_score": 0.77}, separators=(",", ":"), sort_keys=True),
                "sha256:sig-export",
                None,
                None,
                None,
                created_at.isoformat(),
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
                "dep-export-1",
                "d-export-1",
                "RG-701",
                "corr-export",
                "prod",
                "billing",
                "sha256:artifact",
                "sig-export-1",
                created_at.isoformat(),
                "NONE",
                None,
                created_at.isoformat(),
                "github-actions",
                "STRICT",
                "ALLOW",
                "[]",
                "ok",
                created_at.isoformat(),
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
                "cp-export-1",
                "2026-01-15",
                created_at.isoformat(),
                "root",
                1,
                "",
                "checkpoint-hash",
                "ed25519",
                "sig",
                "key-1",
                "http_transparency",
                "anchor-ref",
                json.dumps({}, separators=(",", ":"), sort_keys=True),
                created_at.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_governance_export_quarter_bundle_manifest_hashes_match():
    _reset_db()
    tenant_id = "tenant-export"
    _seed_export_fixture(tenant_id)

    resp = client.post(
        "/governance/export",
        json={"tenant_id": tenant_id, "type": "quarter", "year": 2026, "quarter": 1},
        headers=jwt_headers(tenant_id=tenant_id, roles=["admin"], scopes=["policy:read"]),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/zip")

    with zipfile.ZipFile(io.BytesIO(resp.content), "r") as bundle:
        names = set(bundle.namelist())
        expected = {
            "manifest.json",
            "decisions.ndjson",
            "policies.ndjson",
            "approvals.ndjson",
            "overrides.ndjson",
            "signals.ndjson",
            "deployments.ndjson",
            "anchors.ndjson",
            "integrity_summary.json",
            "verification_instructions.txt",
        }
        assert expected <= names

        manifest = json.loads(bundle.read("manifest.json").decode("utf-8"))
        file_hashes = manifest["file_hashes"]
        record_counts = manifest["record_counts"]

        for filename, expected_hash in file_hashes.items():
            content = bundle.read(filename)
            assert hashlib.sha256(content).hexdigest() == expected_hash

        decisions_lines = [
            line for line in bundle.read("decisions.ndjson").decode("utf-8").splitlines() if line.strip()
        ]
        parsed_decisions = [json.loads(line) for line in decisions_lines]
        assert len(parsed_decisions) == record_counts["decisions.ndjson"]
        assert parsed_decisions[0]["decision_id"] == "d-export-1"
