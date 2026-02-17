from pathlib import Path

import yaml

from releasegate.policy.lint import lint_compiled_policies


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
