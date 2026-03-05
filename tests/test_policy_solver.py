from releasegate.policy.analysis.solver import analyze_policies


def test_solver_detects_conflict_when_same_scope_different_approvals():
    report = analyze_policies(
        policies=[
            {
                "rules": [
                    {
                        "id": "r1",
                        "precedence": 1,
                        "match": {"project": "PAY", "workflow": "release", "transition": "deploy", "environment": "prod"},
                        "result": "ALLOW",
                        "require": {"approvals": 1, "roles": ["EM"]},
                    },
                    {
                        "id": "r2",
                        "precedence": 2,
                        "match": {"project": "PAY", "workflow": "release", "transition": "deploy", "environment": "prod"},
                        "result": "ALLOW",
                        "require": {"approvals": 2, "roles": ["EM"]},
                    },
                ]
            }
        ],
    )
    assert report["summary"]["conflict_count"] >= 1
    assert any(item.get("type") == "REQUIREMENT_CONFLICT" for item in report["conflicts"])


def test_solver_detects_gap_when_transition_uncovered():
    report = analyze_policies(
        policies=[
            {
                "rules": [
                    {
                        "id": "r1",
                        "precedence": 1,
                        "match": {"project": "PAY", "workflow": "release", "transition": "deploy", "environment": "prod"},
                        "result": "ALLOW",
                    }
                ]
            }
        ],
        coverage_targets=[
            {"project": "PAY", "workflow": "release", "transition": "deploy", "environment": "prod"},
            {"project": "PAY", "workflow": "release", "transition": "close", "environment": "prod"},
        ],
    )
    assert report["summary"]["gap_count"] >= 1
    assert any(item.get("scope", {}).get("transition") == "close" for item in report["gaps"])


def test_solver_detects_shadowed_rule_when_more_general_precedes_specific():
    report = analyze_policies(
        policies=[
            {
                "rules": [
                    {
                        "id": "general",
                        "precedence": 1,
                        "match": {"project": "PAY", "workflow": "release", "transition": "*", "environment": "prod"},
                        "result": "ALLOW",
                    },
                    {
                        "id": "specific",
                        "precedence": 2,
                        "match": {"project": "PAY", "workflow": "release", "transition": "deploy", "environment": "prod"},
                        "result": "BLOCK",
                    },
                ]
            }
        ],
    )
    assert report["summary"]["shadowed_rule_count"] >= 1
    assert any(item.get("rule_id") == "specific" for item in report["shadowed_rules"])


def test_solver_reports_ambiguity_when_two_rules_same_precedence():
    report = analyze_policies(
        policies=[
            {
                "rules": [
                    {
                        "id": "r1",
                        "precedence": 5,
                        "match": {"project": "PAY", "workflow": "release", "transition": "deploy", "environment": "prod"},
                        "result": "ALLOW",
                    },
                    {
                        "id": "r2",
                        "precedence": 5,
                        "match": {"project": "PAY", "workflow": "release", "transition": "deploy", "environment": "prod"},
                        "result": "BLOCK",
                    },
                ]
            }
        ],
    )
    assert report["summary"]["ambiguity_count"] >= 1
    assert report["ambiguities"]
