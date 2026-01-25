"""
Privileged Code Change Detection Control (SEC-PR-003).

Detects changes to sensitive/privileged code paths that require higher scrutiny.
"""
from typing import Dict, Any, List, Set
from .types import ControlBase, ControlContext, ControlSignalSet, Finding

class PrivilegedChangeControl(ControlBase):
    """
    Privileged code change detection.
    
    Identifies changes to sensitive paths defined in compliancebot.yaml:
    - Authentication/authorization code
    - Payment processing
    - Cryptographic operations
    - Database migrations
    - Infrastructure-as-code
    """
    
    def execute(self, ctx: ControlContext) -> ControlSignalSet:
        """
        Execute privileged change detection.
        
        Args:
            ctx: Control execution context
        
        Returns:
            Control signals and findings
        """
        # Get privileged paths from config
        privileged_paths = ctx.config.get("privileged_paths", {})
        
        # Categories of privilege
        categories = {
            "auth": privileged_paths.get("auth", []),
            "payment": privileged_paths.get("payment", []),
            "crypto": privileged_paths.get("crypto", []),
            "migrations": privileged_paths.get("migrations", []),
            "infra": privileged_paths.get("infra", []),
        }
        
        # Track which files match which categories
        triggered_categories: Dict[str, List[str]] = {
            cat: [] for cat in categories.keys()
        }
        
        findings: List[Finding] = []
        
        # Check each changed file
        for file_path in ctx.diff.keys():
            for category, patterns in categories.items():
                if self._matches_any_pattern(file_path, patterns):
                    triggered_categories[category].append(file_path)
                    
                    # Create a finding for this privileged change
                    finding = Finding(
                        control_id="SEC-PR-003",
                        rule_id=f"SEC-PR-003.{category.upper()}",
                        severity="HIGH",
                        message=f"Privileged code change detected: {category}",
                        file_path=file_path,
                        line_number=None,
                        evidence={
                            "category": category,
                            "privilege_level": "HIGH",
                            "requires_security_review": True,
                            "patterns_matched": [
                                p for p in patterns 
                                if self._matches_pattern(file_path, p)
                            ]
                        }
                    )
                    findings.append(finding)
        
        # Generate signals
        signals: Dict[str, Any] = {
            "privileged.detected": len(findings) > 0,
            "privileged.count": len(findings),
            "privileged.categories": list(set(
                cat for cat, files in triggered_categories.items() if files
            )),
        }
        
        # Add per-category signals
        for category, files in triggered_categories.items():
            signals[f"privileged.{category}.detected"] = len(files) > 0
            signals[f"privileged.{category}.count"] = len(files)
        
        return ControlSignalSet(
            signals=signals,
            findings=findings
        )
    
    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """
        Check if a file path matches a pattern.
        
        Supports:
        - Exact match: "auth/login.py"
        - Prefix match: "auth/*"
        - Suffix match: "*.sql"
        - Contains: "*migration*"
        """
        if pattern == file_path:
            return True
        
        if pattern.startswith("*") and pattern.endswith("*"):
            # Contains
            return pattern[1:-1] in file_path
        elif pattern.startswith("*"):
            # Suffix
            return file_path.endswith(pattern[1:])
        elif pattern.endswith("*"):
            # Prefix
            return file_path.startswith(pattern[:-1])
        
        return False
    
    def _matches_any_pattern(self, file_path: str, patterns: List[str]) -> bool:
        """Check if file matches any pattern in the list."""
        return any(self._matches_pattern(file_path, p) for p in patterns)

