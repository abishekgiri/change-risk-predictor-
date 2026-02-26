from releasegate.policy.analyzer import detect_transition_coverage


def test_detect_transition_coverage_passes_when_rule_covers_all_risk_bands():
    issues = detect_transition_coverage(
        {
            "required_transitions": ["31"],
            "transition_rules": [{"transition_id": "31", "result": "ALLOW"}],
        }
    )
    assert issues == []


def test_detect_transition_coverage_reports_missing_risk_paths():
    issues = detect_transition_coverage(
        {
            "required_transitions": [{"transition_id": "31", "environment": "prod"}],
            "transition_rules": [
                {
                    "transition_id": "31",
                    "environment": "prod",
                    "conditions": {"risk": "HIGH"},
                    "result": "ALLOW",
                }
            ],
        }
    )
    codes = {issue.get("code") for issue in issues}
    assert "RULE_NO_COVERAGE" in codes

