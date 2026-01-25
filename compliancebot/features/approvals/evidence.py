"""
Convert approval findings to universal evidence format.
"""
from typing import List
from compliancebot.controls.types import Finding
from .types import ApprovalFinding

def approval_to_finding(approval: ApprovalFinding) -> Finding:
    """
    Convert an ApprovalFinding to universal Finding format.
    
    Args:
        approval: The approval finding
    
    Returns:
        Universal Finding object
    """
    requirement = approval.requirement
    
    # Determine severity based on satisfaction
    if not approval.satisfied:
        severity = "HIGH" if requirement.role in ["security", "compliance"] else "MEDIUM"
        message = f"Missing {approval.missing_count} required {requirement.role} approval(s)"
    else:
        severity = "LOW"
        message = f"Approval requirement satisfied: {requirement.count} {requirement.role} approval(s)"
    
    return Finding(
        control_id="SEC-PR-004",
        rule_id=f"SEC-PR-004.{requirement.role.upper()}",
        severity=severity,
        message=message,
        file_path="", # Approvals are PR-level, not file-specific
        line_number=None,
        evidence={
            "requirement_role": requirement.role,
            "requirement_count": requirement.count,
            "actual_count": approval.actual_count,
            "satisfied": approval.satisfied,
            "valid_reviewers": approval.valid_reviewers,
            "stale_reviewers": approval.stale_reviewers,
            "missing_count": approval.missing_count
        }
    )

def approvals_to_findings(approvals: List[ApprovalFinding]) -> List[Finding]:
    """
    Convert multiple ApprovalFindings to universal Finding format.
    
    Args:
        approvals: List of approval findings
    
    Returns:
        List of universal Finding objects
    """
    return [approval_to_finding(a) for a in approvals]

