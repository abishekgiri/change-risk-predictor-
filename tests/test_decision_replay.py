import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets, PolicyBinding
from releasegate.server import app
from releasegate.storage import get_storage_backend
from releasegate.utils.canonical import canonical_json
from tests.auth_helpers import jwt_headers


client = TestClient(app)


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


def test_replay_endpoint_recomputes_status_and_policy_hash():
    repo = f"replay-{uuid.uuid4().hex[:8]}"
    pr_number = 101
    policy_dict = {
        "policy_id": "RG-POL-1",
        "version": "1.0.0",
        "name": "Block high risk",
        "description": "Block when risk is high",
        "scope": "pull_request",
        "enabled": True,
        "controls": [
            {"signal": "raw.risk.level", "operator": "==", "value": "HIGH"},
        ],
        "enforcement": {"result": "BLOCK", "message": "High risk blocked"},
        "metadata": {"source": "unit-test"},
    }
    binding = PolicyBinding(
        policy_id="RG-POL-1",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy_dict),
        policy=policy_dict,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])

    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="BLOCKED",
        context_id=f"jira-{repo}-{pr_number}",
        message="Policy Check (Open -> Ready): BLOCKED",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="actor-123",
        reason_code="POLICY_BLOCKED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
                "risk": {"level": "HIGH"},
                "labels": [],
            },
            "policies_requested": ["RG-POL-1"],
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["RG-1"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    resp = client.post(
        f"/decisions/{stored.decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision_id"] == stored.decision_id
    assert body["original_status"] == "BLOCKED"
    assert body["replay_status"] == "BLOCKED"
    assert body["status_match"] is True
    assert body["policy_hash_match"] is True
    assert body["input_hash_match"] is True
    assert body["decision_hash_match"] is True
    assert body["replay_hash_match"] is True
    assert body["matches_original"] is True
    assert body["match"] is True
    assert body["mismatch_reason"] is None
    assert body["diff"] == []
    assert body["replay_id"]
    assert body["triggered_policies"] == ["RG-POL-1"]
    assert body["repo"] == repo
    assert body["pr_number"] == pr_number
    assert body["deterministic"]["match"] is True
    assert body["deterministic"]["diff"] == []
    assert body["meta"]["replay_id"] == body["replay_id"]
    assert body["meta"]["status"] == "COMPLETED"
    assert body["meta"]["actor"]

    storage = get_storage_backend()
    replay_row = storage.fetchone(
        """
        SELECT replay_id, decision_id, match, status, diff_json
        FROM audit_decision_replays
        WHERE tenant_id = ? AND replay_id = ?
        """,
        ("tenant-test", body["replay_id"]),
    )
    assert replay_row is not None
    assert replay_row["decision_id"] == stored.decision_id
    assert int(replay_row["match"]) == 1
    assert replay_row["status"] == "COMPLETED"
    assert json.loads(replay_row["diff_json"]) == []


def test_replay_endpoint_invalid_state_returns_match_false_not_422():
    repo = f"replay-missing-bindings-{uuid.uuid4().hex[:8]}"
    pr_number = 102
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="SKIPPED",
        context_id=f"jira-{repo}-{pr_number}",
        message="SKIPPED: invalid policy references",
        policy_bundle_hash="any",
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        reason_code="INVALID_POLICY_REFERENCE",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
            },
            "policies_requested": ["RG-POL-1"],
        },
        policy_bindings=[],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["RG-2"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    resp = client.post(
        f"/decisions/{stored.decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["match"] is False
    assert body["deterministic"]["match"] is False
    assert body["meta"]["status"] == "INVALID_STORED_STATE"
    assert body["deterministic"]["diff"]["error"] == "STORED_DECISION_INVALID"
    assert "no policy bindings" in body["deterministic"]["diff"]["details"].lower()


def test_replay_endpoint_returns_diff_when_output_mismatches():
    repo = f"replay-mismatch-{uuid.uuid4().hex[:8]}"
    pr_number = 103
    policy_dict = {
        "policy_id": "RG-POL-2",
        "version": "1.0.0",
        "name": "Block high risk",
        "description": "Block when risk is high",
        "scope": "pull_request",
        "enabled": True,
        "controls": [
            {"signal": "raw.risk.level", "operator": "==", "value": "HIGH"},
        ],
        "enforcement": {"result": "BLOCK", "message": "High risk blocked"},
        "metadata": {"source": "unit-test"},
    }
    binding = PolicyBinding(
        policy_id="RG-POL-2",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy_dict),
        policy=policy_dict,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="ALLOWED by stale decision payload",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="actor-999",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
                "risk": {"level": "HIGH"},
                "labels": [],
            },
            "policies_requested": ["RG-POL-2"],
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["RG-3"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)

    resp = client.post(
        f"/decisions/{stored.decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["match"] is False
    assert body["status_match"] is False
    assert body["replay_status"] == "BLOCKED"
    assert isinstance(body["diff"], list) and body["diff"]
    assert any(item.get("path") == "/status" for item in body["diff"])
    assert body["deterministic"]["match"] is False


def test_replay_endpoint_deterministic_block_is_identical_across_runs():
    repo = f"replay-deterministic-{uuid.uuid4().hex[:8]}"
    pr_number = 104
    policy_dict = {
        "policy_id": "RG-POL-3",
        "version": "1.0.0",
        "name": "Allow low risk",
        "description": "Allow low risk PRs",
        "scope": "pull_request",
        "enabled": True,
        "controls": [
            {"signal": "raw.risk.level", "operator": "==", "value": "LOW"},
        ],
        "enforcement": {"result": "ALLOW", "message": "Allowed"},
        "metadata": {"source": "unit-test"},
    }
    binding = PolicyBinding(
        policy_id="RG-POL-3",
        policy_version="1.0.0",
        policy_hash=_policy_hash(policy_dict),
        policy=policy_dict,
    )
    bundle_hash = _bindings_hash([binding.model_dump(mode="json")])
    decision = Decision(
        timestamp=datetime.now(timezone.utc),
        release_status="ALLOWED",
        context_id=f"jira-{repo}-{pr_number}",
        message="ALLOWED by deterministic replay test",
        policy_bundle_hash=bundle_hash,
        evaluation_key=f"{repo}:{pr_number}:{uuid.uuid4().hex}",
        actor_id="actor-deterministic",
        reason_code="POLICY_ALLOWED",
        inputs_present={"releasegate_risk": True},
        input_snapshot={
            "signal_map": {
                "repo": repo,
                "pr_number": pr_number,
                "diff": {},
                "risk": {"level": "LOW"},
                "labels": [],
            },
            "policies_requested": ["RG-POL-3"],
        },
        policy_bindings=[binding],
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": ["RG-4"]},
        ),
    )
    stored = AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number)
    params = {"tenant_id": "tenant-test"}
    headers = jwt_headers(scopes=["policy:read"])

    first = client.post(f"/decisions/{stored.decision_id}/replay", params=params, headers=headers)
    second = client.post(f"/decisions/{stored.decision_id}/replay", params=params, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    first_det = first.json()["deterministic"]
    second_det = second.json()["deterministic"]
    assert canonical_json(first_det) == canonical_json(second_det)


def test_replay_endpoint_corrupt_stored_payload_returns_mismatch_and_persists_event():
    storage = get_storage_backend()
    repo = f"replay-corrupt-{uuid.uuid4().hex[:8]}"
    decision_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    storage.execute(
        """
        INSERT INTO audit_decisions (
            decision_id,
            tenant_id,
            context_id,
            repo,
            pr_number,
            release_status,
            policy_bundle_hash,
            engine_version,
            decision_hash,
            input_hash,
            policy_hash,
            replay_hash,
            full_decision_json,
            created_at,
            evaluation_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            decision_id,
            "tenant-test",
            f"jira-{repo}-105",
            repo,
            105,
            "ALLOWED",
            "bundle-hash",
            "0.2.0",
            "decision-hash",
            "input-hash",
            "policy-hash",
            "replay-hash",
            "{invalid-json",
            created_at,
            f"{repo}:105:{uuid.uuid4().hex}",
        ),
    )

    resp = client.post(
        f"/decisions/{decision_id}/replay",
        params={"tenant_id": "tenant-test"},
        headers=jwt_headers(scopes=["policy:read"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["match"] is False
    assert body["meta"]["status"] == "INVALID_STORED_STATE"
    assert body["deterministic"]["diff"]["error"] == "STORED_DECISION_INVALID"
    assert body["replay_id"]

    replay_row = storage.fetchone(
        """
        SELECT replay_id, match, status, diff_json
        FROM audit_decision_replays
        WHERE tenant_id = ? AND replay_id = ?
        """,
        ("tenant-test", body["replay_id"]),
    )
    assert replay_row is not None
    assert int(replay_row["match"]) == 0
    assert replay_row["status"] == "INVALID_STORED_STATE"
    diff_json = json.loads(replay_row["diff_json"])
    assert isinstance(diff_json, list) and diff_json
    assert diff_json[0]["error"] == "STORED_DECISION_INVALID"
