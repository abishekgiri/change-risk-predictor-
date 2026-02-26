import os
from datetime import datetime, timedelta, timezone

import pytest

from releasegate.config import DB_PATH
from releasegate.policy.releases import (
    activate_policy_release,
    create_policy_release,
    get_active_policy_release,
    promote_policy_release,
    rollback_policy_release,
    run_policy_release_scheduler,
)
from releasegate.policy.snapshots import build_resolved_policy_snapshot, store_resolved_policy_snapshot
from releasegate.storage.schema import init_db


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def _make_snapshot(tenant_id: str, env: str, rule_id: str):
    snapshot = build_resolved_policy_snapshot(
        policy_id="releasegate.default",
        policy_version="1",
        resolution_inputs={"env": env},
        resolved_policy={"rules": [{"id": rule_id}]},
    )
    return store_resolved_policy_snapshot(tenant_id=tenant_id, snapshot=snapshot)


def test_policy_release_activate_updates_active_pointer(clean_db):
    tenant = "tenant-test"
    snapshot = _make_snapshot(tenant, "dev", "DEV-RULE-1")
    release = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="dev",
        snapshot_id=snapshot["snapshot_id"],
        state="DRAFT",
        created_by="alice",
    )
    active = activate_policy_release(
        tenant_id=tenant,
        release_id=release["release_id"],
        actor_id="alice",
    )
    assert active["state"] == "ACTIVE"

    pointer = get_active_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="dev",
    )
    assert pointer is not None
    assert pointer["active_release_id"] == release["release_id"]
    assert pointer["snapshot"]["snapshot"]["resolved_policy"]["rules"][0]["id"] == "DEV-RULE-1"


def test_policy_release_scheduler_promotes_due_scheduled_release(clean_db):
    tenant = "tenant-test"
    dev_snapshot = _make_snapshot(tenant, "dev", "DEV-RULE-1")
    dev_release = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="dev",
        snapshot_id=dev_snapshot["snapshot_id"],
        state="ACTIVE",
        created_by="alice",
    )
    assert dev_release["state"] == "ACTIVE"

    past_due = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    promoted = promote_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        source_env="dev",
        target_env="staging",
        state="SCHEDULED",
        effective_at=past_due,
        created_by="alice",
    )
    assert promoted["state"] == "SCHEDULED"

    scheduler = run_policy_release_scheduler(tenant_id=tenant, actor_id="scheduler")
    assert scheduler["activated_count"] == 1
    active_staging = get_active_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="staging",
    )
    assert active_staging is not None
    assert active_staging["release"]["state"] == "ACTIVE"


def test_policy_release_rollback_switches_pointer_to_previous_snapshot(clean_db):
    tenant = "tenant-test"
    snapshot_v1 = _make_snapshot(tenant, "prod", "PROD-RULE-1")
    release_v1 = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snapshot_v1["snapshot_id"],
        state="ACTIVE",
        created_by="alice",
    )
    snapshot_v2 = _make_snapshot(tenant, "prod", "PROD-RULE-2")
    release_v2 = create_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        snapshot_id=snapshot_v2["snapshot_id"],
        state="ACTIVE",
        created_by="alice",
    )
    assert release_v2["state"] == "ACTIVE"

    rolled_back = rollback_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
        to_release_id=release_v1["release_id"],
        actor_id="alice",
    )
    assert rolled_back["state"] == "ACTIVE"

    active_prod = get_active_policy_release(
        tenant_id=tenant,
        policy_id="releasegate.default",
        target_env="prod",
    )
    assert active_prod is not None
    assert active_prod["active_release_id"] == rolled_back["release_id"]
    assert active_prod["snapshot"]["snapshot"]["resolved_policy"]["rules"][0]["id"] == "PROD-RULE-1"
