"""
Convert secret findings to universal evidence format.
"""
from typing import List
from compliancebot.controls.types import Finding
from .types import SecretFinding

def secret_to_finding(secret: SecretFinding) -> Finding:
    """
    Convert a SecretFinding to universal Finding format.
    
    Args:
        secret: The secret finding
    
    Returns:
        Universal Finding object
    """
    return Finding(
        control_id="SEC-PR-002",
        rule_id=secret.rule_id,
        severity=secret.severity,
        message=f"Secret detected: {secret.rule_name}",
        file_path=secret.file_path,
        line_number=secret.line_number,
        evidence={
            "rule_name": secret.rule_name,
            "matched_value_masked": secret.mask_value(),
            "line_content": secret.line_content,
            "diff_hunk": secret.diff_hunk,
            "diff_line_index": secret.diff_line_index,
            # Fingerprint for deduplication
            "fingerprint": f"{secret.file_path}:{secret.line_number}:{secret.rule_id}"
        }
    )

def secrets_to_findings(secrets: List[SecretFinding]) -> List[Finding]:
    """
    Convert multiple SecretFindings to universal Finding format.
    
    Args:
        secrets: List of secret findings
    
    Returns:
        List of universal Finding objects
    """
    return [secret_to_finding(s) for s in secrets]

