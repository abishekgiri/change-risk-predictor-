"""
Unit tests for Approval Enforcement.
"""
import pytest
from datetime import datetime
from compliancebot.features.approvals.types import Review, ApprovalRequirement
from compliancebot.features.approvals.validator import (
 is_review_stale,
 get_reviewer_roles,
 validate_approvals
)
from compliancebot.controls.approvals import ApprovalsControl
from compliancebot.controls.types import ControlContext

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
 
 # Mock provider would normally fetch reviews
 # For this test, we'll test the no-provider case
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
 
 assert result.signals["approvals.required"] is True
 assert result.signals["approvals.satisfied"] is False
 assert result.signals["approvals.unsatisfied_count"] == 1

if __name__ == "__main__":
 pytest.main([__file__, "-v"])
