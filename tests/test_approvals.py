"""
Unit tests for Approval Enforcement.
"""
import pytest
from datetime import datetime
from releasegate.signals.approvals.types import Review, ApprovalRequirement
from releasegate.signals.approvals.validator import (
 is_review_stale,
 get_reviewer_roles,
 validate_approvals
)
from releasegate.enforcement.approvals import ApprovalsControl
from releasegate.enforcement.types import ControlContext


class MockProvider:
    def __init__(self, reviews, pr_author="author", codeowners="", team_members=None):
        self._reviews = reviews
        self._pr_author = pr_author
        self._codeowners = codeowners
        self._team_members = team_members or {}

    def get_reviews(self, _repo, _pr_number):
        return self._reviews

    def get_pr_author(self, _repo, _pr_number):
        return self._pr_author

    def get_file_content(self, _repo, path, ref=None):
        if path in (".github/CODEOWNERS", "CODEOWNERS"):
            return self._codeowners
        return None

    def get_team_members(self, team_slug):
        return self._team_members.get(team_slug, [])

def test_stale_review_detection():
 """Test detection of stale reviews."""
 review = Review(
 reviewer="alice",
 state="APPROVED",
 submitted_at=datetime.now(),
 commit_id="abc123"
 )
 
 # Same commit - not stale
 assert not is_review_stale(review, "abc123")
 
 # Different commit - stale
 assert is_review_stale(review, "def456")

def test_reviewer_roles():
 """Test reviewer role lookup."""
 config = {
 "reviewer_roles": {
 "alice": ["security", "developer"],
 "bob": ["manager"],
 "charlie": ["developer"]
 }
 }
 
 assert get_reviewer_roles("alice", config) == ["security", "developer"]
 assert get_reviewer_roles("bob", config) == ["manager"]
 assert get_reviewer_roles("unknown", config) == ["developer"] # Default

def test_approval_validation_satisfied():
 """Test approval validation when requirements are met."""
 reviews = [
 Review("alice", "APPROVED", datetime.now(), "head123"),
 Review("bob", "APPROVED", datetime.now(), "head123"),
 ]
 
 requirements = [
 ApprovalRequirement(role="security", count=1),
 ApprovalRequirement(role="manager", count=1),
 ]
 
 config = {
 "reviewer_roles": {
 "alice": ["security"],
 "bob": ["manager"]
 }
 }
 
 findings = validate_approvals(reviews, requirements, "head123", config)
 
 assert len(findings) == 2
 assert all(f.satisfied for f in findings)
 assert findings[0].actual_count == 1 # security
 assert findings[1].actual_count == 1 # manager

def test_approval_validation_unsatisfied():
 """Test approval validation when requirements are not met."""
 reviews = [
 Review("alice", "APPROVED", datetime.now(), "head123"),
 ]
 
 requirements = [
 ApprovalRequirement(role="security", count=2), # Need 2, have 1
 ]
 
 config = {
 "reviewer_roles": {
 "alice": ["security"]
 }
 }
 
 findings = validate_approvals(reviews, requirements, "head123", config)
 
 assert len(findings) == 1
 assert not findings[0].satisfied
 assert findings[0].actual_count == 1
 assert findings[0].missing_count == 1

def test_stale_approvals_ignored():
 """Test that stale approvals are not counted."""
 reviews = [
 Review("alice", "APPROVED", datetime.now(), "old123"), # Stale
 Review("bob", "APPROVED", datetime.now(), "head123"), # Fresh
 ]
 
 requirements = [
 ApprovalRequirement(role="security", count=2),
 ]
 
 config = {
 "reviewer_roles": {
 "alice": ["security"],
 "bob": ["security"]
 }
 }
 
 findings = validate_approvals(reviews, requirements, "head123", config)
 
 assert len(findings) == 1
 assert not findings[0].satisfied # Only 1 fresh approval
 assert findings[0].actual_count == 1
 assert "alice" in findings[0].stale_reviewers
 assert "bob" in findings[0].valid_reviewers

def test_non_approved_reviews_ignored():
 """Test that non-APPROVED reviews are ignored."""
 reviews = [
 Review("alice", "CHANGES_REQUESTED", datetime.now(), "head123"),
 Review("bob", "COMMENTED", datetime.now(), "head123"),
 Review("charlie", "APPROVED", datetime.now(), "head123"),
 ]
 
 requirements = [
 ApprovalRequirement(role="developer", count=1),
 ]
 
 config = {
 "reviewer_roles": {
 "alice": ["developer"],
 "bob": ["developer"],
 "charlie": ["developer"]
 }
 }
 
 findings = validate_approvals(reviews, requirements, "head123", config)
 
 assert len(findings) == 1
 assert findings[0].satisfied
 assert findings[0].actual_count == 1
 assert findings[0].valid_reviewers == ["charlie"]

def test_approvals_control_no_requirements():
 """Test ApprovalsControl when no requirements configured."""
 control = ApprovalsControl()
 
 context = ControlContext(
 repo="test/repo",
 pr_number=123,
 diff={},
 config={}, # No approval_requirements
 provider=None
 )
 
 result = control.execute(context)
 
 assert result.signals["approvals.required"] is False
 assert result.signals["approvals.satisfied"] is True
 assert len(result.findings) == 0

def test_approvals_control_with_requirements():
 """Test ApprovalsControl with configured requirements."""
 control = ApprovalsControl()
 
 # No provider => fail-open skip for missing approval data.
 context = ControlContext(
 repo="test/repo",
 pr_number=123,
 diff={},
 config={
 "approval_requirements": [
 {"role": "security", "count": 1}
 ],
 "head_sha": "head123"
 },
 provider=None # No provider = no reviews = fails validation
 )
 
 result = control.execute(context)
 
 assert result.signals["approvals.required"] is False
 assert result.signals["approvals.satisfied"] is True
 assert result.signals["approvals.skipped"] is True
 assert result.signals["approvals.data_available"] is False
 assert len(result.findings) == 0


def test_approvals_control_role_aware_signal_and_reasons():
 control = ApprovalsControl()
 now = datetime.now()
 provider = MockProvider(
 reviews=[
 Review("alice", "APPROVED", now, "head123"),
 Review("bob", "APPROVED", now, "head123"),
 ],
 pr_author="alice",
 codeowners="* @alice @org/security",
 team_members={"org/security": ["sec-user"]},
 )

 context = ControlContext(
 repo="test/repo",
 pr_number=123,
 diff={},
 config={
 "head_sha": "head123",
 "approvals": {
 "min_total": 2,
 "disallow_self_approval": True,
 "require_codeowner": True,
 "require_security_team": True,
 "security_team_slugs": ["org/security"],
 },
 },
 provider=provider,
 )

 result = control.execute(context)

 assert result.signals["approvals.required"] is True
 assert result.signals["approvals.satisfied"] is False
 assert "approvals" in result.signals
 assert result.signals["approvals"]["self_approval_detected"] is True
 assert "APPROVALS_INSUFFICIENT" in result.signals["approvals"]["reason_codes"]
 assert "SECURITY_APPROVAL_REQUIRED" in result.signals["approvals"]["reason_codes"]


def test_approvals_control_role_aware_passes_with_required_roles():
 control = ApprovalsControl()
 now = datetime.now()
 provider = MockProvider(
 reviews=[
 Review("owner-user", "APPROVED", now, "head123"),
 Review("sec-user", "APPROVED", now, "head123"),
 ],
 pr_author="author",
 codeowners="* @owner-user @org/security",
 team_members={"org/security": ["sec-user"]},
 )
 context = ControlContext(
 repo="test/repo",
 pr_number=999,
 diff={},
 config={
 "head_sha": "head123",
 "approvals": {
 "min_total": 2,
 "disallow_self_approval": True,
 "require_codeowner": True,
 "require_security_team": True,
 "security_team_slugs": ["org/security"],
 },
 },
 provider=provider,
 )

 result = control.execute(context)
 assert result.signals["approvals.satisfied"] is True
 assert result.signals["approvals"]["reason_codes"] == []
 assert result.signals["approvals"]["codeowner_approved"] is True
 assert result.signals["approvals"]["security_team_approved"] is True
 assert result.signals["approvals"]["approved_by"] == ["owner-user", "sec-user"]

if __name__ == "__main__":
 pytest.main([__file__, "-v"])
