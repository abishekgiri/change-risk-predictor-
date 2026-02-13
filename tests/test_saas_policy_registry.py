from types import SimpleNamespace

from releasegate.saas.policy import resolve_effective_policy, resolve_scoped_policy


def test_resolve_scoped_policy_applies_broad_then_specific():
    base_config = {
        "high_threshold": 80,
        "policy_registry": {
            "scopes": [
                {
                    "id": "prod",
                    "match": {"environment": "PRODUCTION"},
                    "config": {"required_approvals": 1},
                },
                {
                    "id": "transition-31",
                    "match": {"transition_id": "31"},
                    "config": {"required_approvals": 3},
                },
                {
                    "id": "prod-payments",
                    "match": {"environment": "PRODUCTION", "project_key": "PAY"},
                    "config": {"required_approvals": 2},
                },
            ]
        },
    }
    context = {
        "environment": "production",
        "project_key": "pay",
        "transition_id": "31",
    }

    resolved = resolve_scoped_policy(base_config, context=context)

    assert resolved["matched_scope_ids"] == ["prod", "transition-31", "prod-payments"]
    assert resolved["matched_scope_count"] == 3
    assert resolved["config"]["required_approvals"] == 2


def test_resolve_scoped_policy_supports_alias_and_list_matching():
    base_config = {
        "policy_registry": {
            "scopes": [
                {
                    "id": "project-alias",
                    "scope": {"project": ["OPS", "PLATFORM"]},
                    "config": {"strict_mode": True},
                },
                {
                    "id": "transition-alias",
                    "scope": {"transition": ["Ready for Production", "Done"]},
                    "config": {"require_cab": True},
                },
            ]
        },
    }
    context = {
        "project_key": "ops",
        "transition_name": "ready for production",
    }

    resolved = resolve_scoped_policy(base_config, context=context)

    assert resolved["matched_scope_ids"] == ["project-alias", "transition-alias"]
    assert resolved["config"]["strict_mode"] is True
    assert resolved["config"]["require_cab"] is True


def test_resolve_effective_policy_includes_context_and_scope_matches():
    repo = SimpleNamespace(
        id=10,
        org_id=100,
        full_name="org/service",
        name="service",
        strictness_level="block",
        policy_override={
            "policy_registry": {
                "scopes": [
                    {
                        "id": "repo-prod",
                        "match": {"environment": "PRODUCTION"},
                        "config": {"required_approvals": 3},
                    }
                ]
            }
        },
    )
    org = SimpleNamespace(
        id=100,
        default_policy_config={
            "required_approvals": 1,
            "policy_registry": {
                "scopes": [
                    {
                        "id": "org-prod",
                        "match": {"environment": "PRODUCTION"},
                        "config": {"required_approvals": 2},
                    }
                ]
            },
        },
    )

    class FakeQuery:
        def __init__(self, result):
            self.result = result

        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return self.result

    class FakeSession:
        def query(self, model):
            if model.__name__ == "Repository":
                return FakeQuery(repo)
            if model.__name__ == "Organization":
                return FakeQuery(org)
            raise AssertionError(f"unexpected model {model}")

    effective = resolve_effective_policy(
        session=FakeSession(),
        repo_id=repo.id,
        context={"environment": "production"},
    )

    assert effective["repo_id"] == repo.id
    assert effective["org_id"] == org.id
    assert effective["repo_name"] == "org/service"
    assert effective["strictness"] == "block"
    assert "policy_resolution_hash" in effective
    assert isinstance(effective["policy_resolution_hash"], str)
    assert "repo" in effective["policy_scope"]
    assert "scope" in effective["policy_scope"]
    assert effective["matched_scope_ids"] == ["repo-prod"]
    assert effective["matched_scope_count"] == 1
    assert effective["context"]["environment"] == "production"
    assert effective["config"]["required_approvals"] == 3


def test_resolve_effective_policy_applies_environment_layer_after_repo():
    repo = SimpleNamespace(
        id=11,
        org_id=101,
        full_name="org/payments",
        name="payments",
        strictness_level="block",
        policy_override={
            "required_approvals": 2,
            "environment_policies": {
                "PRODUCTION": {"required_approvals": 4},
            },
        },
    )
    org = SimpleNamespace(
        id=101,
        default_policy_config={"required_approvals": 1},
    )

    class FakeQuery:
        def __init__(self, result):
            self.result = result

        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return self.result

    class FakeSession:
        def query(self, model):
            if model.__name__ == "Repository":
                return FakeQuery(repo)
            if model.__name__ == "Organization":
                return FakeQuery(org)
            raise AssertionError(f"unexpected model {model}")

    effective = resolve_effective_policy(
        session=FakeSession(),
        repo_id=repo.id,
        context={"environment": "production"},
    )

    assert effective["config"]["required_approvals"] == 4
    assert effective["environment_scope"] == "PRODUCTION"
    assert effective["policy_scope"][:3] == ["org", "repo", "environment"]
