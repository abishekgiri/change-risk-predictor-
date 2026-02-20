from releasegate.governance.sod import evaluate_separation_of_duties


def test_sod_detects_requester_approver_conflict():
    violation = evaluate_separation_of_duties(
        actors={
            "override_requested_by": {"alice@example.com"},
            "override_approved_by": {"alice@example.com"},
        },
        config={"enabled": True},
    )
    assert violation is not None
    assert violation["reason_code"] == "SOD_REQUESTER_APPROVER_CONFLICT"


def test_sod_detects_pr_author_approver_conflict():
    violation = evaluate_separation_of_duties(
        actors={
            "pr_author": {"alice@example.com"},
            "override_approved_by": {"alice@example.com"},
        },
        config={"enabled": True},
    )
    assert violation is not None
    assert violation["reason_code"] == "SOD_PR_AUTHOR_APPROVER_CONFLICT"


def test_sod_passes_when_principals_are_distinct():
    violation = evaluate_separation_of_duties(
        actors={
            "override_requested_by": {"alice@example.com"},
            "override_approved_by": {"bob@example.com"},
            "pr_author": {"carol@example.com"},
        },
        config={"enabled": True},
    )
    assert violation is None
