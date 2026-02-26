from pathlib import Path

import yaml

from releasegate.policy.lint import lint_compiled_policies, lint_registry_policy


def _write_policy(root: Path, name: str, payload: dict) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_policy_lint_detects_internal_contradiction(tmp_path):
    policy_dir = tmp_path / "compiled"
    _write_policy(
        policy_dir,
        "P1.yaml",
        {
            "policy_id": "P1",
            "name": "Contradictory",
            "scope": "pull_request",
            "controls": [
                {"signal": "risk.level", "operator": "==", "value": "HIGH"},
                {"signal": "risk.level", "operator": "!=", "value": "HIGH"},
            ],
            "enforcement": {"result": "BLOCK", "message": "x"},
        },
    )

    report = lint_compiled_policies(policy_dir="compiled", strict_schema=True, base_dir=tmp_path)

    assert report["ok"] is False
    assert any(i["code"] == "CONTRADICTORY_EQUALITY_NEGATION" for i in report["issues"])


def test_policy_lint_detects_ambiguous_overlap(tmp_path):
    policy_dir = tmp_path / "compiled"
    common_controls = [
        {"signal": "risk.level", "operator": "==", "value": "HIGH"},
    ]
    _write_policy(
        policy_dir,
        "P1.yaml",
        {
            "policy_id": "P1",
            "name": "Ambiguous-1",
            "scope": "pull_request",
            "controls": common_controls,
            "enforcement": {"result": "BLOCK", "message": "x"},
        },
    )
    _write_policy(
        policy_dir,
        "P2.yaml",
        {
            "policy_id": "P2",
            "name": "Ambiguous-2",
            "scope": "pull_request",
            "controls": common_controls,
            "enforcement": {"result": "WARN", "message": "y"},
        },
    )

    report = lint_compiled_policies(policy_dir="compiled", strict_schema=True, base_dir=tmp_path)

    assert report["ok"] is False
    assert any(i["code"] == "AMBIGUOUS_OVERLAP" for i in report["issues"])


def test_policy_lint_detects_conflicting_overlap_same_priority(tmp_path):
    policy_dir = tmp_path / "compiled"
    _write_policy(
        policy_dir,
        "P1.yaml",
        {
            "policy_id": "P1",
            "name": "Block high risk",
            "scope": "pull_request",
            "controls": [{"signal": "risk.score", "operator": ">=", "value": 70}],
            "enforcement": {"result": "BLOCK", "message": "x"},
            "metadata": {"priority": 100},
        },
    )
    _write_policy(
        policy_dir,
        "P2.yaml",
        {
            "policy_id": "P2",
            "name": "Warn very high risk",
            "scope": "pull_request",
            "controls": [{"signal": "risk.score", "operator": ">=", "value": 80}],
            "enforcement": {"result": "WARN", "message": "y"},
            "metadata": {"priority": 100},
        },
    )

    report = lint_compiled_policies(policy_dir="compiled", strict_schema=True, base_dir=tmp_path)

    assert report["ok"] is False
    assert any(i["code"] == "CONTRADICTORY_RULES" for i in report["issues"])


def test_policy_lint_detects_shadowed_rule(tmp_path):
    policy_dir = tmp_path / "compiled"
    _write_policy(
        policy_dir,
        "P1.yaml",
        {
            "policy_id": "P1",
            "name": "Block high risk",
            "scope": "pull_request",
            "controls": [{"signal": "risk.score", "operator": ">=", "value": 50}],
            "enforcement": {"result": "BLOCK", "message": "x"},
            "metadata": {"priority": 90},
        },
    )
    _write_policy(
        policy_dir,
        "P2.yaml",
        {
            "policy_id": "P2",
            "name": "Block critical files at same threshold",
            "scope": "pull_request",
            "controls": [
                {"signal": "risk.score", "operator": ">=", "value": 50},
                {"signal": "change.critical_files_count", "operator": ">", "value": 0},
            ],
            "enforcement": {"result": "BLOCK", "message": "y"},
            "metadata": {"priority": 100},
        },
    )

    report = lint_compiled_policies(policy_dir="compiled", strict_schema=True, base_dir=tmp_path)

    assert any(i["code"] == "RULE_UNREACHABLE_SHADOWED" for i in report["issues"])


def test_policy_lint_detects_coverage_gap(tmp_path):
    policy_dir = tmp_path / "compiled"
    _write_policy(
        policy_dir,
        "P1.yaml",
        {
            "policy_id": "P1",
            "name": "Prod rule",
            "scope": "pull_request",
            "controls": [{"signal": "risk.level", "operator": "==", "value": "HIGH"}],
            "enforcement": {"result": "BLOCK", "message": "x"},
            "metadata": {"environment": "prod", "workflow_id": "wf-release", "transition_id": "2"},
        },
    )

    report = lint_compiled_policies(
        policy_dir="compiled",
        strict_schema=True,
        base_dir=tmp_path,
        coverage_targets=[
            {"env": "prod", "workflow_id": "wf-release", "transition_id": "2"},
            {"env": "prod", "workflow_id": "wf-release", "transition_id": "3"},
        ],
    )

    assert report["ok"] is False
    assert any(i["code"] == "COVERAGE_GAP" for i in report["issues"])


def test_policy_lint_passes_valid_policies(tmp_path):
    policy_dir = tmp_path / "compiled"
    _write_policy(
        policy_dir,
        "P1.yaml",
        {
            "policy_id": "P1",
            "name": "Risk Block",
            "scope": "pull_request",
            "controls": [
                {"signal": "risk.level", "operator": "==", "value": "HIGH"},
            ],
            "enforcement": {"result": "BLOCK", "message": "x"},
        },
    )
    _write_policy(
        policy_dir,
        "P2.yaml",
        {
            "policy_id": "P2",
            "name": "Risk Warn",
            "scope": "pull_request",
            "controls": [
                {"signal": "risk.score", "operator": ">", "value": 30},
                {"signal": "risk.score", "operator": "<=", "value": 60},
            ],
            "enforcement": {"result": "WARN", "message": "y"},
        },
    )

    report = lint_compiled_policies(policy_dir="compiled", strict_schema=True, base_dir=tmp_path)

    assert report["ok"] is True
    assert report["error_count"] == 0


def test_registry_lint_detects_conflicts_and_uncovered_transitions():
    report = lint_registry_policy(
        {
            "strict_fail_closed": True,
            "required_transitions": ["2", "3"],
            "transition_rules": [
                {"transition_id": "2", "result": "ALLOW"},
                {"transition_id": "2", "result": "BLOCK"},
            ],
        }
    )

    assert report["ok"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "TRANSITION_UNCOVERED" in codes
    assert "OVERLAPPING_RULES" in codes
    assert "CONTRADICTORY_RULES" in codes


def test_registry_lint_detects_impossible_approval_requirements():
    report = lint_registry_policy(
        {
            "approval_requirements": {
                "min_approvals": 3,
                "required_roles": ["security", "platform"],
                "role_capacity": {"security": 1, "platform": 1},
            }
        }
    )

    assert report["ok"] is False
    assert any(issue["code"] == "APPROVAL_REQUIREMENT_IMPOSSIBLE" for issue in report["issues"])


def test_registry_lint_detects_invalid_nested_rule_logic():
    report = lint_registry_policy(
        {
            "rules": [
                {"id": "bad-empty-all", "when": {"all": []}, "result": "ALLOW"},
                {"id": "bad-unknown", "when": {"foo": "bar"}, "result": "ALLOW"},
            ]
        }
    )

    assert report["ok"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "RULE_INVALID_LOGIC" in codes


def test_registry_lint_detects_conflicting_rule_requirements():
    report = lint_registry_policy(
        {
            "rules": [
                {
                    "id": "rule-1",
                    "when": {"risk": "HIGH"},
                    "require": {"approvals": 2, "roles": ["Security"]},
                    "required_approvals": 1,
                    "required_roles": ["EM"],
                    "result": "WARN",
                }
            ]
        }
    )

    assert report["ok"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "CONTRADICTORY_RULES" in codes


def test_registry_lint_detects_ambiguous_overlap_for_wildcard_selectors():
    report = lint_registry_policy(
        {
            "transition_rules": [
                {"transition_id": "2", "project_id": "", "priority": 100, "result": "ALLOW"},
                {"transition_id": "2", "project_id": "proj-a", "priority": 100, "result": "BLOCK"},
            ]
        }
    )

    assert report["ok"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "AMBIGUOUS_OVERLAP" in codes


def test_registry_lint_detects_shadowed_narrower_rule():
    report = lint_registry_policy(
        {
            "transition_rules": [
                {"transition_id": "2", "project_id": "", "priority": 10, "result": "ALLOW"},
                {"transition_id": "2", "project_id": "proj-a", "priority": 20, "result": "ALLOW"},
            ]
        }
    )

    codes = {issue["code"] for issue in report["issues"]}
    assert "RULE_UNREACHABLE_SHADOWED" in codes


def test_registry_lint_detects_transition_coverage_gaps():
    report = lint_registry_policy(
        {
            "required_transitions": ["2"],
            "transition_rules": [
                {"transition_id": "2", "conditions": {"risk": "HIGH"}, "result": "ALLOW"},
            ],
        }
    )

    assert report["ok"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "RULE_NO_COVERAGE" in codes
