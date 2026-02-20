import os
import sqlite3

import pytest

from releasegate.config import DB_PATH
from releasegate.policy.registry import (
    activate_registry_policy,
    create_registry_policy,
    get_registry_policy,
    list_registry_policies,
    resolve_registry_policy,
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


def test_registry_policy_activation_blocked_when_lint_errors_exist(clean_db):
    tenant = "tenant-registry"
    created = create_registry_policy(
        tenant_id=tenant,
        scope_type="transition",
        scope_id="2",
        policy_json={
            "strict_fail_closed": True,
            "required_transitions": ["2"],
            "transition_rules": [],
        },
        created_by="alice",
        status="DRAFT",
    )
    assert created["status"] == "DRAFT"
    assert any(issue["code"] == "TRANSITION_UNCOVERED" for issue in created["lint_errors"])

    with pytest.raises(ValueError, match="lint errors"):
        activate_registry_policy(
            tenant_id=tenant,
            policy_id=created["policy_id"],
            actor_id="alice",
        )


def test_registry_activation_supersedes_previous_active_scope(clean_db):
    tenant = "tenant-registry"
    first = create_registry_policy(
        tenant_id=tenant,
        scope_type="project",
        scope_id="PROJ",
        policy_json={"required_approvals": 1},
        created_by="alice",
        status="ACTIVE",
    )
    assert first["status"] == "ACTIVE"

    second = create_registry_policy(
        tenant_id=tenant,
        scope_type="project",
        scope_id="PROJ",
        policy_json={"required_approvals": 2},
        created_by="alice",
        status="ACTIVE",
    )
    assert second["status"] == "ACTIVE"
    assert second["supersedes_policy_id"] == first["policy_id"]

    first_after = get_registry_policy(tenant_id=tenant, policy_id=first["policy_id"])
    assert first_after is not None
    assert first_after["status"] == "DEPRECATED"

    policies = list_registry_policies(tenant_id=tenant, scope_type="project", scope_id="PROJ")
    assert [p["policy_id"] for p in policies][:2] == [second["policy_id"], first["policy_id"]]


def test_registry_inheritance_resolves_org_project_workflow_transition(clean_db):
    tenant = "tenant-registry"
    create_registry_policy(
        tenant_id=tenant,
        scope_type="org",
        scope_id=tenant,
        policy_json={"required_approvals": 1, "strict_fail_closed": True, "policy_source": "org"},
        created_by="alice",
        status="ACTIVE",
    )
    create_registry_policy(
        tenant_id=tenant,
        scope_type="project",
        scope_id="PROJ",
        policy_json={"required_approvals": 2, "policy_source": "project"},
        created_by="alice",
        status="ACTIVE",
    )
    create_registry_policy(
        tenant_id=tenant,
        scope_type="workflow",
        scope_id="wf-release",
        policy_json={"strict_fail_closed": False, "policy_source": "workflow"},
        created_by="alice",
        status="ACTIVE",
    )
    create_registry_policy(
        tenant_id=tenant,
        scope_type="transition",
        scope_id="2",
        policy_json={"transition_flag": "ship", "policy_source": "transition"},
        created_by="alice",
        status="ACTIVE",
    )

    first = resolve_registry_policy(
        tenant_id=tenant,
        org_id=tenant,
        project_id="PROJ",
        workflow_id="wf-release",
        transition_id="2",
        rollout_key="RG-1",
    )
    second = resolve_registry_policy(
        tenant_id=tenant,
        org_id=tenant,
        project_id="PROJ",
        workflow_id="wf-release",
        transition_id="2",
        rollout_key="RG-1",
    )

    assert first["effective_policy_hash"] == second["effective_policy_hash"]
    assert first["component_policy_ids"] == second["component_policy_ids"]
    assert first["effective_policy"]["required_approvals"] == 2
    assert first["effective_policy"]["strict_fail_closed"] is False
    assert first["effective_policy"]["transition_flag"] == "ship"
    assert first["effective_policy"]["policy_source"] == "transition"


def test_registry_rollout_falls_back_to_previous_deprecated_policy(clean_db):
    tenant = "tenant-registry"
    v1 = create_registry_policy(
        tenant_id=tenant,
        scope_type="transition",
        scope_id="31",
        policy_json={"required_approvals": 1, "marker": "v1"},
        created_by="alice",
        status="ACTIVE",
    )
    v2 = create_registry_policy(
        tenant_id=tenant,
        scope_type="transition",
        scope_id="31",
        policy_json={"required_approvals": 9, "marker": "v2"},
        created_by="alice",
        status="ACTIVE",
        rollout_percentage=0,
        rollout_scope="transition",
    )

    resolved = resolve_registry_policy(
        tenant_id=tenant,
        org_id=tenant,
        project_id="PROJ",
        workflow_id="wf-release",
        transition_id="31",
        rollout_key="RG-31",
    )

    assert resolved["effective_policy"]["marker"] == "v1"
    assert resolved["effective_policy"]["required_approvals"] == 1
    assert resolved["component_policy_ids"] == [v1["policy_id"]]
    component = resolved["components"][0]
    assert component["rollout"]["enabled"] is True
    assert component["rollout"]["selected"] is False
    assert component["rollout"]["superseded_by"] == v2["policy_id"]


def test_registry_activation_is_idempotent_for_active_policy(clean_db):
    tenant = "tenant-registry"
    created = create_registry_policy(
        tenant_id=tenant,
        scope_type="workflow",
        scope_id="wf-release",
        policy_json={"required_approvals": 2},
        created_by="alice",
        status="ACTIVE",
    )
    first_activated_at = created["activated_at"]
    first_supersedes = created["supersedes_policy_id"]

    activated_again = activate_registry_policy(
        tenant_id=tenant,
        policy_id=created["policy_id"],
        actor_id="alice",
    )
    assert activated_again["status"] == "ACTIVE"
    assert activated_again["policy_id"] == created["policy_id"]
    assert activated_again["supersedes_policy_id"] == first_supersedes
    assert activated_again["activated_at"] == first_activated_at


def test_registry_enforces_single_active_per_scope(clean_db):
    tenant = "tenant-registry"
    first = create_registry_policy(
        tenant_id=tenant,
        scope_type="project",
        scope_id="PROJ",
        policy_json={"required_approvals": 1},
        created_by="alice",
        status="ACTIVE",
    )
    second = create_registry_policy(
        tenant_id=tenant,
        scope_type="project",
        scope_id="PROJ",
        policy_json={"required_approvals": 2},
        created_by="alice",
        status="DRAFT",
    )

    conn = sqlite3.connect(DB_PATH)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                UPDATE policy_registry_entries
                SET status = 'ACTIVE'
                WHERE tenant_id = ? AND policy_id = ?
                """,
                (tenant, second["policy_id"]),
            )
            conn.commit()
    finally:
        conn.close()

    first_after = get_registry_policy(tenant_id=tenant, policy_id=first["policy_id"])
    second_after = get_registry_policy(tenant_id=tenant, policy_id=second["policy_id"])
    assert first_after is not None and first_after["status"] == "ACTIVE"
    assert second_after is not None and second_after["status"] == "DRAFT"


def test_registry_payload_is_immutable(clean_db):
    tenant = "tenant-registry"
    created = create_registry_policy(
        tenant_id=tenant,
        scope_type="transition",
        scope_id="2",
        policy_json={"required_approvals": 1},
        created_by="alice",
        status="DRAFT",
    )

    conn = sqlite3.connect(DB_PATH)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                UPDATE policy_registry_entries
                SET policy_json = ?
                WHERE tenant_id = ? AND policy_id = ?
                """,
                ('{"required_approvals":99}', tenant, created["policy_id"]),
            )
            conn.commit()
    finally:
        conn.close()


def test_registry_rollout_selection_is_deterministic_for_same_key(clean_db):
    tenant = "tenant-registry"
    create_registry_policy(
        tenant_id=tenant,
        scope_type="transition",
        scope_id="45",
        policy_json={"marker": "stable"},
        created_by="alice",
        status="ACTIVE",
        rollout_percentage=10,
        rollout_scope="transition",
    )

    first = resolve_registry_policy(
        tenant_id=tenant,
        org_id=tenant,
        project_id="PROJ",
        workflow_id="wf-release",
        transition_id="45",
        rollout_key="RG-45",
    )
    second = resolve_registry_policy(
        tenant_id=tenant,
        org_id=tenant,
        project_id="PROJ",
        workflow_id="wf-release",
        transition_id="45",
        rollout_key="RG-45",
    )

    assert first["component_policy_ids"] == second["component_policy_ids"]
    assert first["effective_policy_hash"] == second["effective_policy_hash"]
    assert first["components"] == second["components"]
