"""
Environment Boundary Violations Control (ENV-PR-001).

Detects production config/secrets leaking into non-production code.
"""
from typing import Dict, Any, List
import re
from .types import ControlBase, ControlContext, ControlSignalSet, Finding


class EnvironmentBoundaryControl(ControlBase):
    """
    Environment boundary violation detection.
    
    Prevents production URLs, API keys, or config from appearing
    in non-production code paths.
    """
    
    def execute(self, ctx: ControlContext) -> ControlSignalSet:
        """
        Execute environment boundary checking.
        
        Args:
            ctx: Control execution context
            
        Returns:
            Control signals and findings
        """
        # Get environment patterns from config
        env_config = ctx.config.get("environment_patterns", {})
        prod_patterns = env_config.get("production", [])
        nonprod_paths = env_config.get("nonprod_paths", [])
        
        if not prod_patterns or not nonprod_paths:
            # No configuration, pass by default
            return ControlSignalSet(
                signals={
                    "env_boundary.configured": False,
                    "env_boundary.violations": 0
                },
                findings=[]
            )
        
        findings: List[Finding] = []
        
        # Scan non-prod files for prod patterns
        for file_path, diff_content in ctx.diff.items():
            if self._is_nonprod_path(file_path, nonprod_paths):
                violations = self._scan_for_prod_patterns(
                    file_path,
                    diff_content,
                    prod_patterns
                )
                findings.extend(violations)
        
        # Generate signals
        signals: Dict[str, Any] = {
            "env_boundary.configured": True,
            "env_boundary.violations": len(findings),
            "env_boundary.has_violations": len(findings) > 0
        }
        
        return ControlSignalSet(
            signals=signals,
            findings=findings
        )
    
    def _is_nonprod_path(self, file_path: str, nonprod_paths: List[str]) -> bool:
        """Check if file is in a non-production path."""
        for pattern in nonprod_paths:
            if pattern in file_path or file_path.startswith(pattern):
                return True
        return False
    
    def _scan_for_prod_patterns(
        self,
        file_path: str,
        diff_content: str,
        prod_patterns: List[str]
    ) -> List[Finding]:
        """Scan diff for production patterns."""
        findings = []
        lines = diff_content.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            # Only scan added lines
            if not line.startswith("+") or line.startswith("+++"):
                continue
            
            line_content = line[1:]  # Remove '+'
            
            for pattern in prod_patterns:
                if re.search(pattern, line_content, re.IGNORECASE):
                    finding = Finding(
                        control_id="ENV-PR-001",
                        rule_id="ENV-PR-001.PROD_LEAK",
                        severity="HIGH",
                        message=f"Production pattern detected in non-prod file: {file_path}",
                        file_path=file_path,
                        line_number=line_num,
                        evidence={
                            "pattern": pattern,
                            "line_content": line_content.strip(),
                            "inferred_environment": "production",
                            "violation_type": "prod_config_in_nonprod"
                        }
                    )
                    findings.append(finding)
        
        return findings
