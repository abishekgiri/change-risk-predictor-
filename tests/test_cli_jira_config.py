from __future__ import annotations

import sys
from pathlib import Path
from textwrap import dedent

from releasegate.cli import build_parser, main


def _write(path: Path, content: str) -> None:
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")


def test_cli_parser_includes_validate_jira_config():
    parser = build_parser()
    args = parser.parse_args(["validate-jira-config"])
    assert args.cmd == "validate-jira-config"


def test_cli_validate_jira_config_command_returns_zero_for_valid_files(tmp_path, monkeypatch):
    transition_map = tmp_path / "jira_transition_map.yaml"
    role_map = tmp_path / "jira_role_map.yaml"
    _write(
        transition_map,
        """
        version: 1
        transitions:
          - transition_id: "31"
            gate: SEC-PR-001
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

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releasegate",
            "validate-jira-config",
            "--transition-map",
            str(transition_map),
            "--role-map",
            str(role_map),
            "--format",
            "json",
        ],
    )
    rc = main()
    assert rc == 0
