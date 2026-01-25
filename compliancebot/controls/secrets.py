"""
Secrets Control (SEC-PR-002).

Prevents secrets from being committed to source code.
"""
from typing import Dict, Any
from .types import ControlBase, ControlContext, ControlSignalSet, Finding
from compliancebot.features.secrets.scanner import scan_pr_diff
from compliancebot.features.secrets.evidence import secrets_to_findings

class SecretsControl(ControlBase):
    """
    Secret scanning control.
    
    Scans PR diffs for hardcoded secrets using 2-factor detection:
    - Known patterns (AWS keys, GitHub tokens, etc.)
    - Generic high-entropy strings with secret-related context
    """
    
    def execute(self, ctx: ControlContext) -> ControlSignalSet:
        """
        Execute secret scanning.
        
        Args:
            ctx: Control execution context
        
        Returns:
            Control signals and findings
        """
        # Scan all files in the PR diff
        secret_findings = scan_pr_diff(ctx.diff)
        
        # Convert to universal Finding format
        findings = secrets_to_findings(secret_findings)
        
        # Generate signals for policy evaluation
        signals: Dict[str, Any] = {
            "secrets.detected": len(findings) > 0,
            "secrets.count": len(findings),
            "secrets.high_severity_count": sum(
                1 for f in findings if f.severity == "HIGH"
            ),
            "secrets.medium_severity_count": sum(
                1 for f in findings if f.severity == "MEDIUM"
            ),
        }
        
        # Add individual secret types
        rule_counts: Dict[str, int] = {}
        for finding in findings:
            rule_id = finding.rule_id
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        
        for rule_id, count in rule_counts.items():
            signals[f"secrets.rule.{rule_id}"] = count
        
        return ControlSignalSet(
            signals=signals,
            findings=findings
        )

