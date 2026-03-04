import os

from fastapi.testclient import TestClient

from releasegate.config import DB_PATH
from releasegate.policy.releases import create_policy_release
from releasegate.policy.snapshots import build_resolved_policy_snapshot, store_resolved_policy_snapshot
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _snapshot(tenant_id: str, env: str, rule_id: str):
    snapshot = build_resolved_policy_snapshot(
        policy_id="releasegate.default",
        policy_version="1",
        resolution_inputs={"env": env},
        resolved_policy={"rules": [{"id": rule_id}]},
    )
    return store_resolved_policy_snapshot(tenant_id=tenant_id, snapshot=snapshot)


def test_policy_rollout_api_canary_promote_and_rollback_flow():
    _reset_db()
    tenant = "tenant-rollout-api"
    admin_headers = jwt_headers(tenant_id=tenant, roles=["admin"], scopes=["policy:write", "policy:read"])
    read_headers = jwt_headers(tenant_id=tenant, roles=["admin"], scopes=["policy:read"])

    snap_old = _snapshot(tenant, "prod", "OLD")
    old_release = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snap_old["snapshot_id"],
        state="ACTIVE",
        created_by="alice",
    )
    snap_new = _snapshot(tenant, "prod", "NEW")
    new_release = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snap_new["snapshot_id"],
        state="DRAFT",
        created_by="alice",
    )

    rollout_resp = client.post(
        "/policy/rollouts",
        headers=admin_headers,
        json={
            "tenant_id": tenant,
            "policy_id": "releasegate.default",
            "target_env": "prod",
            "to_release_id": new_release["release_id"],
            "mode": "canary",
            "canary_percent": 50,
        },
    )
    assert rollout_resp.status_code == 200, rollout_resp.text
    rollout = rollout_resp.json()
    assert rollout["state"] == "RUNNING"
    assert rollout["from_release_id"] == old_release["release_id"]

    resolved_first = client.get(
        "/policy/releases/active",
        headers=read_headers,
        params={
            "tenant_id": tenant,
            "policy_id": "releasegate.default",
            "target_env": "prod",
            "rollout_key": "RG-key-1",
        },
    )
    resolved_second = client.get(
        "/policy/releases/active",
        headers=read_headers,
        params={
            "tenant_id": tenant,
            "policy_id": "releasegate.default",
            "target_env": "prod",
            "rollout_key": "RG-key-1",
        },
    )
    assert resolved_first.status_code == 200, resolved_first.text
    assert resolved_second.status_code == 200, resolved_second.text
    assert resolved_first.json()["active_release_id"] == resolved_second.json()["active_release_id"]

    promote_resp = client.post(
        f"/policy/rollouts/{rollout['rollout_id']}/promote",
        headers=admin_headers,
        json={"tenant_id": tenant},
    )
    assert promote_resp.status_code == 200, promote_resp.text
    assert promote_resp.json()["state"] == "COMPLETED"

    resolved_after_promote = client.get(
        "/policy/releases/active",
        headers=read_headers,
        params={
            "tenant_id": tenant,
            "policy_id": "releasegate.default",
            "target_env": "prod",
            "rollout_key": "any-key",
        },
    )
    assert resolved_after_promote.status_code == 200, resolved_after_promote.text
    assert resolved_after_promote.json()["active_release_id"] == new_release["release_id"]

    rollback_resp = client.post(
        f"/policy/rollouts/{rollout['rollout_id']}/rollback",
        headers=admin_headers,
        json={"tenant_id": tenant},
    )
    assert rollback_resp.status_code == 200, rollback_resp.text
    assert rollback_resp.json()["state"] == "ROLLED_BACK"

    resolved_after_rollback = client.get(
        "/policy/releases/active",
        headers=read_headers,
        params={
            "tenant_id": tenant,
            "policy_id": "releasegate.default",
            "target_env": "prod",
            "rollout_key": "any-key",
        },
    )
    assert resolved_after_rollback.status_code == 200, resolved_after_rollback.text
    assert resolved_after_rollback.json()["active_release_id"] == old_release["release_id"]
