import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import pytest

from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets, PolicyBinding
from releasegate.storage import get_storage_backend
from releasegate.storage.schema import init_db


POSTGRES_TEST_DSN_ENV = "RELEASEGATE_TEST_POSTGRES_DSN"


def _policy_hash(policy: dict) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _bindings_hash(bindings: list[dict]) -> str:
    material = []
    for binding in sorted(bindings, key=lambda x: x.get("policy_id", "")):
        material.append(
            {
                "policy_id": binding.get("policy_id"),
                "policy_version": binding.get("policy_version"),
                "policy_hash": binding.get("policy_hash"),
            }
        )
    payload = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@pytest.fixture()
def postgres_env(monkeypatch):
    dsn = os.getenv(POSTGRES_TEST_DSN_ENV)
    if not dsn:
        pytest.skip(f"set {POSTGRES_TEST_DSN_ENV} to run postgres integration tests")

    monkeypatch.setenv("RELEASEGATE_STORAGE_BACKEND", "postgres")
    monkeypatch.setenv("RELEASEGATE_POSTGRES_DSN", dsn)
    get_storage_backend.cache_clear()
    init_db()
    yield
    get_storage_backend.cache_clear()


def test_postgres_append_only_triggers_block_update_and_delete(postgres_env):
    storage = get_storage_backend()
    tenant_id = f"tenant-pg-{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()
    replay_id = str(uuid.uuid4())
    node_id = str(uuid.uuid4())
    edge_id = str(uuid.uuid4())

    storage.execute(
        """
        INSERT INTO audit_decision_replays (
            tenant_id, replay_id, decision_id, match, diff_json, ran_engine_version, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            replay_id,
            str(uuid.uuid4()),
            True,
            json.dumps([], separators=(",", ":"), sort_keys=True),
            "0.2.0",
            now,
        ),
    )
    storage.execute(
        """
        INSERT INTO evidence_nodes (
            tenant_id, node_id, type, ref, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            node_id,
            "DECISION",
            f"decision:{uuid.uuid4()}",
            json.dumps({"k": "v"}, separators=(",", ":"), sort_keys=True),
            now,
        ),
    )
    storage.execute(
        """
        INSERT INTO evidence_edges (
            tenant_id, edge_id, from_node_id, to_node_id, type, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            edge_id,
            node_id,
            node_id,
            "RELATED_TO",
            json.dumps({}, separators=(",", ":"), sort_keys=True),
            now,
        ),
    )

    with pytest.raises(Exception, match="append-only|not allowed"):
        storage.execute(
            "UPDATE audit_decision_replays SET match = ? WHERE tenant_id = ? AND replay_id = ?",
            (False, tenant_id, replay_id),
        )
    with pytest.raises(Exception, match="append-only|not allowed"):
        storage.execute(
            "DELETE FROM audit_decision_replays WHERE tenant_id = ? AND replay_id = ?",
            (tenant_id, replay_id),
        )

    with pytest.raises(Exception, match="append-only|not allowed"):
        storage.execute(
            "UPDATE evidence_nodes SET hash = ? WHERE tenant_id = ? AND node_id = ?",
            ("abc", tenant_id, node_id),
        )
    with pytest.raises(Exception, match="append-only|not allowed"):
        storage.execute(
            "DELETE FROM evidence_nodes WHERE tenant_id = ? AND node_id = ?",
            (tenant_id, node_id),
        )

    with pytest.raises(Exception, match="append-only|not allowed"):
        storage.execute(
            "UPDATE evidence_edges SET type = ? WHERE tenant_id = ? AND edge_id = ?",
            ("USED_POLICY", tenant_id, edge_id),
        )
    with pytest.raises(Exception, match="append-only|not allowed"):
        storage.execute(
            "DELETE FROM evidence_edges WHERE tenant_id = ? AND edge_id = ?",
            (tenant_id, edge_id),
        )


def test_postgres_recorder_flow_persists_decision_snapshot_and_graph(postgres_env):
    tenant_id = f"tenant-pg-{uuid.uuid4().hex[:10]}"
    repo = f"pg-int-{uuid.uuid4().hex[:8]}"
    pr_number = 88
    issue_key = "RG-POSTGRES-1"

    policy_dict = {
        "policy_id": "RG-PG-1",
        "version": "1.0.0",
        "name": "Allow low risk",
        "description": "Allow when risk low",
        "scope": "pull_request",
        "enabled": True,
        "controls": [{"signal": "raw.risk.level", "operator": "==", "value": "LOW"}],
        "enforcement": {"result": "ALLOW", "message": "Approved"},
    }
    binding = PolicyBinding(
        policy_id="RG-PG-1",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy_dict),
        policy=policy_dict,
        tenant_id=tenant_id,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])
    decision = Decision(
        tenant_id=tenant_id,
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="allowed",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="pg-int-user",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {"repo": repo, "pr_number": pr_number, "diff": {}, "risk": {"level": "LOW"}},
            "policies_requested": ["RG-PG-1"],
            "issue_key": issue_key,
            "transition_id": "2",
            "environment": "PRODUCTION",
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="abc123",
            external={"jira": [issue_key]},
        ),
    )
    stored = AuditRecorder.record_with_context(
        decision=decision,
        repo=repo,
        pr_number=pr_number,
        tenant_id=tenant_id,
    )

    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT decision_id FROM audit_decisions WHERE tenant_id = ? AND decision_id = ?",
        (tenant_id, stored.decision_id),
    )
    assert row is not None

    binding_row = storage.fetchone(
        "SELECT snapshot_id, policy_hash FROM policy_decision_records WHERE tenant_id = ? AND decision_id = ?",
        (tenant_id, stored.decision_id),
    )
    assert binding_row is not None
    assert binding_row.get("snapshot_id")
    assert binding_row.get("policy_hash")

    node = storage.fetchone(
        "SELECT node_id FROM evidence_nodes WHERE tenant_id = ? AND type = ? AND ref = ?",
        (tenant_id, "DECISION", stored.decision_id),
    )
    assert node is not None
    edge = storage.fetchone(
        "SELECT edge_id FROM evidence_edges WHERE tenant_id = ? AND from_node_id = ? LIMIT 1",
        (tenant_id, node["node_id"]),
    )
    assert edge is not None

