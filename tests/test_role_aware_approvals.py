from datetime import datetime, timedelta, timezone

from releasegate.signals.approvals.evaluator import (
    evaluate_role_aware_approvals,
    normalize_approval_policy,
)
from releasegate.signals.approvals.types import Review


def _review(reviewer: str, state: str, at: datetime, commit: str = "head123") -> Review:
    return Review(reviewer=reviewer, state=state, submitted_at=at, commit_id=commit)


def test_self_approval_is_excluded_when_disallowed():
    now = datetime.now(timezone.utc)
    policy = normalize_approval_policy(
        {
            "min_total": 2,
            "disallow_self_approval": True,
        }
    )
    result = evaluate_role_aware_approvals(
        reviews=[
            _review("alice", "APPROVED", now),
            _review("bob", "APPROVED", now + timedelta(seconds=1)),
        ],
        policy=policy,
        head_sha="head123",
        pr_author="alice",
    )

    assert result.total_approvals == 1
    assert result.self_approval_detected is True
    assert "APPROVALS_INSUFFICIENT" in result.reason_codes
    assert "SELF_APPROVAL_NOT_ALLOWED" in result.reason_codes


def test_codeowner_requirement_fails_without_codeowner_approval():
    now = datetime.now(timezone.utc)
    policy = normalize_approval_policy(
        {
            "min_total": 1,
            "require_codeowner": True,
        }
    )
    result = evaluate_role_aware_approvals(
        reviews=[_review("bob", "APPROVED", now)],
        policy=policy,
        head_sha="head123",
        pr_author="alice",
        codeowner_users={"alice"},
    )

    assert result.total_approvals == 1
    assert result.codeowner_approved is False
    assert "CODEOWNER_APPROVAL_REQUIRED" in result.reason_codes


def test_codeowner_requirement_passes_with_codeowner_approval():
    now = datetime.now(timezone.utc)
    policy = normalize_approval_policy(
        {
            "min_total": 1,
            "require_codeowner": True,
        }
    )
    result = evaluate_role_aware_approvals(
        reviews=[_review("alice", "APPROVED", now)],
        policy=policy,
        head_sha="head123",
        pr_author="bob",
        codeowner_users={"alice"},
    )

    assert result.codeowner_approved is True
    assert result.reason_codes == []


def test_security_team_requirement_fails_and_passes():
    now = datetime.now(timezone.utc)
    policy = normalize_approval_policy(
        {
            "min_total": 1,
            "require_security_team": True,
            "security_team_slugs": ["org/security"],
        }
    )
    team_members = {"org/security": ["sec-user"]}

    failing = evaluate_role_aware_approvals(
        reviews=[_review("dev-user", "APPROVED", now)],
        policy=policy,
        head_sha="head123",
        pr_author="author",
        team_members_by_slug=team_members,
    )
    passing = evaluate_role_aware_approvals(
        reviews=[_review("sec-user", "APPROVED", now + timedelta(seconds=1))],
        policy=policy,
        head_sha="head123",
        pr_author="author",
        team_members_by_slug=team_members,
    )

    assert "SECURITY_APPROVAL_REQUIRED" in failing.reason_codes
    assert passing.security_team_approved is True
    assert passing.reason_codes == []


def test_latest_review_per_user_wins():
    now = datetime.now(timezone.utc)
    policy = normalize_approval_policy({"min_total": 1})
    result = evaluate_role_aware_approvals(
        reviews=[
            _review("alice", "CHANGES_REQUESTED", now),
            _review("alice", "APPROVED", now + timedelta(seconds=10)),
        ],
        policy=policy,
        head_sha="head123",
        pr_author="bob",
    )

    assert result.total_approvals == 1
    assert result.reason_codes == []
