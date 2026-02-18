from __future__ import annotations

import textwrap

import pytest

from releasegate.control_plane.repo_registry import (
    get_repo_entry,
    load_repo_policy_inputs,
    load_repo_registry,
)


def test_repo_registry_loads_and_resolves_policy_inputs(tmp_path):
    (tmp_path / "org.yaml").write_text(
        textwrap.dedent(
            """\
            approvals:
              min_total: 1
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "repo.yaml").write_text(
        textwrap.dedent(
            """\
            approvals:
              min_total: 2
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "envs.yaml").write_text(
        textwrap.dedent(
            """\
            production:
              dependency_provenance:
                lockfile_required: true
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "repos.yaml").write_text(
        textwrap.dedent(
            """\
            version: 1
            repos:
              - repo: org/repo
                owners: ["security"]
                enforcement_mode: enforce
                environment: PRODUCTION
                org_policy_path: org.yaml
                repo_policy_path: repo.yaml
                environment_policies_path: envs.yaml
                list_merge_strategies:
                  approvals.security_team_slugs: union
            """
        ),
        encoding="utf-8",
    )

    registry = load_repo_registry("repos.yaml", base_dir=tmp_path)
    entry = get_repo_entry(registry=registry, repo="org/repo")
    assert entry is not None

    cfg = load_repo_policy_inputs(entry=entry, base_dir=tmp_path)
    assert cfg["enforcement"]["mode"] == "enforce"
    assert cfg["environment"] == "PRODUCTION"
    inh = cfg["policy_inheritance"]
    assert inh["org_policy"]["approvals"]["min_total"] == 1
    assert inh["repo_policies"]["org/repo"]["approvals"]["min_total"] == 2
    assert inh["environment_policies"]["production"]["dependency_provenance"]["lockfile_required"] is True
    assert inh["list_merge_strategies"]["approvals.security_team_slugs"] == "union"


def test_repo_registry_rejects_unsupported_version(tmp_path):
    (tmp_path / "repos.yaml").write_text("version: 2\nrepos: []\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_repo_registry("repos.yaml", base_dir=tmp_path)

