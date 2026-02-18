from __future__ import annotations

from releasegate.policy.bundle import build_policy_bundle, validate_policy_bundle


def test_policy_bundle_schema_validation_passes():
    bundle = build_policy_bundle(
        org_policy={"dependency_provenance": {"lockfile_required": True}},
        repo_policy={"approvals": {"min_total": 2}},
        environment="DEV",
        environment_policies={"dev": {"approvals": {"min_total": 3}}},
        list_merge_strategies={"approvals.security_team_slugs": "union"},
    )
    assert validate_policy_bundle(bundle) == []
    assert bundle["schema_version"] == "policy_bundle_v1"
    assert bundle["policy_resolution_hash"]


def test_policy_bundle_is_deterministic():
    args = dict(
        org_policy={"labels": {"a": True}, "approvals": {"security_team_slugs": ["org/sec"]}},
        repo_policy={"labels": {"b": True}, "approvals": {"security_team_slugs": ["org/sec", "org/plat"]}},
        environment="PRODUCTION",
        environment_policies={"production": {"labels": {"c": True}}},
        list_merge_strategies={"approvals.security_team_slugs": "union"},
    )
    first = build_policy_bundle(**args)
    second = build_policy_bundle(**args)
    assert first == second
    assert first["policy_resolution_hash"] == second["policy_resolution_hash"]

