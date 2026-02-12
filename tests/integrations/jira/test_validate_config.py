from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from releasegate.integrations.jira.validate import validate_jira_config_files


def _write(path: Path, content: str) -> None:
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")


def test_validate_jira_config_files_passes_for_valid_templates(tmp_path):
    transition_map = tmp_path / "jira_transition_map.yaml"
    role_map = tmp_path / "jira_role_map.yaml"

    _write(
        transition_map,
        """
        version: 1
        jira:
          project_keys: ["DEMO"]
          issue_types: ["Bug"]
        gate_bindings:
          release_gate: ["SEC-PR-001"]
        transitions:
          - transition_id: "31"
            gate: release_gate
            mode: strict
        """,
    )
    _write(
        role_map,
        """
        version: 1
        roles:
          admin:
            jira_groups: ["jira-administrators"]
          operator:
            jira_project_roles: ["Developers"]
        """,
    )

    report = validate_jira_config_files(
        transition_map_path=str(transition_map),
        role_map_path=str(role_map),
    )
    assert report["ok"] is True
    assert report["error_count"] == 0


def test_validate_jira_config_files_rejects_unknown_gate(tmp_path):
    transition_map = tmp_path / "jira_transition_map.yaml"
    role_map = tmp_path / "jira_role_map.yaml"

    _write(
        transition_map,
        """
        version: 1
        transitions:
          - transition_id: "31"
            gate: not_a_real_gate
        """,
    )
    _write(
        role_map,
        """
        version: 1
        roles:
          admin:
            jira_groups: ["jira-administrators"]
        """,
    )

    report = validate_jira_config_files(
        transition_map_path=str(transition_map),
        role_map_path=str(role_map),
    )
    assert report["ok"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "TRANSITION_GATE_UNKNOWN" in codes


def test_validate_jira_config_files_detects_duplicate_transition_scope(tmp_path):
    transition_map = tmp_path / "jira_transition_map.yaml"
    role_map = tmp_path / "jira_role_map.yaml"

    _write(
        transition_map,
        """
        version: 1
        gate_bindings:
          release_gate: ["SEC-PR-001"]
        transitions:
          - transition_id: "31"
            gate: release_gate
            project_keys: ["DEMO"]
            issue_types: ["Bug"]
          - transition_id: "31"
            gate: release_gate
            project_keys: ["DEMO"]
            issue_types: ["Bug"]
        """,
    )
    _write(
        role_map,
        """
        version: 1
        roles:
          admin:
            jira_groups: ["jira-administrators"]
        """,
    )

    report = validate_jira_config_files(
        transition_map_path=str(transition_map),
        role_map_path=str(role_map),
    )
    assert report["ok"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "TRANSITION_RULE_DUPLICATE" in codes
