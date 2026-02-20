import os

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
