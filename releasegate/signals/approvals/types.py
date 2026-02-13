"""
Approval validation types.
"""
from dataclasses import dataclass
from dataclasses import field
from typing import Optional
from datetime import datetime

@dataclass
class Review:
    """A PR review."""
    reviewer: str
    state: str # APPROVED, CHANGES_REQUESTED, COMMENTED, DISMISSED
    submitted_at: datetime
    commit_id: str # SHA of commit when review was submitted
    
    
@dataclass
class Reviewer:
    """A reviewer with role information."""
    username: str
    roles: list[str] # e.g., ["security", "manager", "developer"]
    
    
@dataclass
class ApprovalRequirement:
    """An approval requirement from config."""
    role: str # Required reviewer role
    count: int # Number of approvals needed from this role
    
    
@dataclass
class ApprovalFinding:
    """An approval validation finding."""
    requirement: ApprovalRequirement
    satisfied: bool
    actual_count: int
    valid_reviewers: list[str] # Who provided valid approvals
    stale_reviewers: list[str] # Who provided stale approvals
    missing_count: int


@dataclass
class RoleAwareApprovalPolicy:
    """Role-aware approval policy config."""

    min_total: int = 1
    disallow_self_approval: bool = True
    require_codeowner: bool = False
    require_security_team: bool = False
    security_team_slugs: list[str] = field(default_factory=list)


@dataclass
class RoleAwareApprovalResult:
    """Role-aware approval evaluation result."""

    min_total_required: int
    total_approvals: int
    disallow_self_approval: bool
    self_approval_detected: bool
    codeowner_required: bool
    codeowner_approved: Optional[bool]
    security_team_required: bool
    security_team_approved: Optional[bool]
    approved_by: list[str]
    reason_codes: list[str]
    security_approvals_count: int = 0
