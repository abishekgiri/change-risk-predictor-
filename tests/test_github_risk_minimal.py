from releasegate.integrations.github_risk import (
    PRRiskInput,
    build_issue_risk_property,
    classify_pr_risk,
    extract_jira_issue_keys,
)


def test_classify_pr_risk_uses_only_metadata_counts():
    assert classify_pr_risk(PRRiskInput(changed_files=21, additions=1, deletions=1)) == "HIGH"
    assert classify_pr_risk(PRRiskInput(changed_files=3, additions=350, deletions=10)) == "MEDIUM"
    assert classify_pr_risk(PRRiskInput(changed_files=3, additions=30, deletions=10)) == "LOW"


def test_build_issue_risk_property_shape():
    metrics = PRRiskInput(changed_files=5, additions=100, deletions=20)
    payload = build_issue_risk_property(
        repo="org/service-api",
        pr_number=184,
        risk_level="HIGH",
        metrics=metrics,
    )
    assert payload["releasegate_risk"] == "HIGH"
    assert payload["source"] == "github"
    assert payload["repo"] == "org/service-api"
    assert payload["pr_number"] == 184
    assert payload["metrics"]["changed_files_count"] == 5
    assert payload["computed_at"].endswith("Z")


def test_extract_jira_issue_keys():
    keys = extract_jira_issue_keys("Fixes APP-123 and SEC-9", "refs APP-123")
    assert keys == {"APP-123", "SEC-9"}
