"""
Approval validator - checks if PR has required approvals.
"""
from typing import List, Dict, Any
from datetime import datetime
from .types import Review, Reviewer, ApprovalRequirement, ApprovalFinding

def is_review_stale(review: Review, head_sha: str) -> bool:
    """
    Check if a review is stale (submitted before latest commit).
    
    Args:
        review: The review to check
        head_sha: Current HEAD SHA of the PR
    
    Returns:
        True if review is stale
    """
    return review.commit_id != head_sha

def get_reviewer_roles(username: str, config: Dict[str, Any]) -> List[str]:
    """
    Get roles for a reviewer from config.
    
    Args:
        username: GitHub username
        config: Configuration with reviewer_roles mapping
    
    Returns:
        List of roles (e.g., ["security", "developer"])
    """
    reviewer_roles = config.get("reviewer_roles", {})
    return reviewer_roles.get(username, ["developer"]) # Default to developer

def validate_approvals(
    reviews: List[Review],
    requirements: List[ApprovalRequirement],
    head_sha: str,
    config: Dict[str, Any]
) -> List[ApprovalFinding]:
    """
    Validate that PR has required approvals.
    
    Args:
        reviews: All reviews on the PR
        requirements: Approval requirements from config
        head_sha: Current HEAD SHA
        config: Configuration with reviewer roles
    
    Returns:
        List of approval findings (one per requirement)
    """
    findings = []
    
    for requirement in requirements:
        # Filter to APPROVED reviews only
        approved_reviews = [r for r in reviews if r.state == "APPROVED"]
        
        # Separate stale vs fresh reviews
        fresh_reviews = []
        stale_reviews = []
        
        for review in approved_reviews:
            reviewer_roles = get_reviewer_roles(review.reviewer, config)
            
            # Check if reviewer has required role
            if requirement.role in reviewer_roles:
                if is_review_stale(review, head_sha):
                    stale_reviews.append(review.reviewer)
                else:
                    fresh_reviews.append(review.reviewer)
        
        # Deduplicate (same reviewer may have multiple reviews)
        valid_reviewers = list(set(fresh_reviews))
        stale_reviewers = list(set(stale_reviews))
        
        actual_count = len(valid_reviewers)
        satisfied = actual_count >= requirement.count
        missing_count = max(0, requirement.count - actual_count)
        
        finding = ApprovalFinding(
            requirement=requirement,
            satisfied=satisfied,
            actual_count=actual_count,
            valid_reviewers=valid_reviewers,
            stale_reviewers=stale_reviewers,
            missing_count=missing_count
        )
        findings.append(finding)
    
    return findings

