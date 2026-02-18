from releasegate.policy.inheritance import resolve_policy_inheritance


def test_policy_inheritance_merges_org_repo_environment_in_order():
    resolved = resolve_policy_inheritance(
        org_policy={
            "required_approvals": 1,
            "labels": {"security": False, "release": False},
        },
        repo_policy={
            "required_approvals": 2,
            "labels": {"release": True},
        },
        environment="PRODUCTION",
        environment_policies={
            "production": {
                "required_approvals": 3,
                "labels": {"security": True},
                "freeze": True,
            }
        },
    )

    assert resolved["policy_scope"] == ["org", "repo", "environment"]
    config = resolved["resolved_policy"]
    assert config["required_approvals"] == 3
    assert config["labels"]["security"] is True
    assert config["labels"]["release"] is True
    assert config["freeze"] is True
    assert config["dependency_provenance"]["lockfile_required"] is False


def test_policy_inheritance_hash_is_deterministic():
    args = {
        "org_policy": {"required_approvals": 1, "labels": {"a": True}},
        "repo_policy": {"labels": {"b": True}},
        "environment": "DEV",
        "environment_policies": {"dev": {"required_approvals": 2}},
    }

    first = resolve_policy_inheritance(**args)
    second = resolve_policy_inheritance(**args)

    assert first["policy_resolution_hash"] == second["policy_resolution_hash"]
    assert first["resolved_policy"] == second["resolved_policy"]


def test_policy_inheritance_preserves_dependency_provenance_rule():
    resolved = resolve_policy_inheritance(
        org_policy={"dependency_provenance": {"lockfile_required": False}},
        repo_policy={"dependency_provenance": {"lockfile_required": True}},
        environment="DEV",
        environment_policies=None,
    )
    assert resolved["resolved_policy"]["dependency_provenance"]["lockfile_required"] is True


def test_policy_inheritance_emits_field_provenance():
    resolved = resolve_policy_inheritance(
        org_policy={
            "required_approvals": 1,
            "labels": {"security": False, "release": False},
        },
        repo_policy={
            "required_approvals": 2,
            "labels": {"release": True},
        },
        environment="PRODUCTION",
        environment_policies={
            "production": {
                "required_approvals": 3,
                "labels": {"security": True},
                "freeze": True,
            }
        },
    )
    provenance = resolved.get("provenance") or {}
    assert provenance["required_approvals"] == ["environment"]
    assert provenance["labels.security"] == ["environment"]
    assert provenance["labels.release"] == ["repo"]
    assert provenance["freeze"] == ["environment"]
    # Default-injected policy defaults must be attributed.
    assert provenance["dependency_provenance.lockfile_required"] == ["default"]


def test_policy_inheritance_list_union_strategy_is_deterministic():
    resolved = resolve_policy_inheritance(
        org_policy={"approvals": {"security_team_slugs": ["org/security"]}},
        repo_policy={"approvals": {"security_team_slugs": ["org/security", "org/platform"]}},
        environment="DEV",
        environment_policies=None,
        list_merge_strategies={"approvals.security_team_slugs": "union"},
    )
    cfg = resolved["resolved_policy"]
    assert cfg["approvals"]["security_team_slugs"] == ["org/platform", "org/security"]
    assert resolved["provenance"]["approvals.security_team_slugs"] == ["org", "repo"]
