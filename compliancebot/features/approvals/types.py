"""
Approval validation types.
"""
from dataclasses import dataclass
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

