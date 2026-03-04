import os

import pytest

from releasegate.config import DB_PATH
from releasegate.policy.releases import create_policy_release
from releasegate.policy.snapshots import build_resolved_policy_snapshot, store_resolved_policy_snapshot
from releasegate.rollout.rollout_service import (
    create_policy_rollout,
    promote_policy_rollout,
    resolve_effective_policy_release,
    rollback_policy_rollout,
)
from releasegate.storage.schema import init_db


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def _snapshot(tenant_id: str, env: str, rule_id: str):
    snapshot = build_resolved_policy_snapshot(
        policy_id="releasegate.default",
        policy_version="1",
        resolution_inputs={"env": env},
        resolved_policy={"rules": [{"id": rule_id}]},
    )
    return store_resolved_policy_snapshot(tenant_id=tenant_id, snapshot=snapshot)


def test_rollout_canary_selection_is_deterministic(clean_db):
    tenant = "tenant-rollout"
    snap_v1 = _snapshot(tenant, "prod", "RULE-OLD")
    release_v1 = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snap_v1["snapshot_id"],
        state="ACTIVE",
        created_by="alice",
    )
    snap_v2 = _snapshot(tenant, "prod", "RULE-NEW")
    release_v2 = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snap_v2["snapshot_id"],
        state="DRAFT",
        created_by="alice",
    )

    rollout = create_policy_rollout(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        to_release_id=release_v2["release_id"],
        mode="canary",
        canary_percent=25,
        created_by="alice",
    )
    assert rollout["state"] == "RUNNING"
    assert rollout["from_release_id"] == release_v1["release_id"]

    first = resolve_effective_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        rollout_key="RG-100",
    )
    second = resolve_effective_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        rollout_key="RG-100",
    )
    assert first is not None
    assert second is not None
    assert first["active_release_id"] == second["active_release_id"]
    assert first.get("rollout", {}).get("state") == "RUNNING"


def test_rollout_promote_switches_all_traffic_to_new_release(clean_db):
    tenant = "tenant-rollout"
    snap_v1 = _snapshot(tenant, "prod", "RULE-OLD")
    release_v1 = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snap_v1["snapshot_id"],
        state="ACTIVE",
        created_by="alice",
    )
    snap_v2 = _snapshot(tenant, "prod", "RULE-NEW")
    release_v2 = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snap_v2["snapshot_id"],
        state="DRAFT",
        created_by="alice",
    )

    rollout = create_policy_rollout(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        to_release_id=release_v2["release_id"],
        mode="canary",
        canary_percent=10,
        created_by="alice",
    )

    promoted = promote_policy_rollout(
        tenant_id=tenant,
        rollout_id=rollout["rollout_id"],
        actor_id="alice",
    )
    assert promoted["state"] == "COMPLETED"

    resolved_a = resolve_effective_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        rollout_key="RG-1",
    )
    resolved_b = resolve_effective_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        rollout_key="RG-99",
    )
    assert resolved_a is not None
    assert resolved_b is not None
    assert resolved_a["active_release_id"] == release_v2["release_id"]
    assert resolved_b["active_release_id"] == release_v2["release_id"]
    assert resolved_a.get("rollout", {}).get("state") == "COMPLETED"

def test_rollout_rollback_restores_previous_release(clean_db):
    tenant = "tenant-rollout"
    snap_v1 = _snapshot(tenant, "prod", "RULE-OLD")
    release_v1 = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snap_v1["snapshot_id"],
        state="ACTIVE",
        created_by="alice",
    )
    snap_v2 = _snapshot(tenant, "prod", "RULE-NEW")
    release_v2 = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snap_v2["snapshot_id"],
        state="DRAFT",
        created_by="alice",
    )

    rollout = create_policy_rollout(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        to_release_id=release_v2["release_id"],
        mode="canary",
        canary_percent=20,
        created_by="alice",
    )
    promote_policy_rollout(
        tenant_id=tenant,
        rollout_id=rollout["rollout_id"],
        actor_id="alice",
    )

    rolled_back = rollback_policy_rollout(
        tenant_id=tenant,
        rollout_id=rollout["rollout_id"],
        actor_id="alice",
    )
    assert rolled_back["state"] == "ROLLED_BACK"
    assert rolled_back["rollback_to_release_id"] == release_v1["release_id"]

    resolved = resolve_effective_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        rollout_key="RG-any",
    )
    assert resolved is not None
    assert resolved["active_release_id"] == release_v1["release_id"]
    assert resolved.get("rollout", {}).get("state") == "ROLLED_BACK"
