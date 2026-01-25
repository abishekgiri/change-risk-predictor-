"""
Base types and interfaces for Phase 3 controls.

All controls must implement ControlBase and return ControlSignalSet.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
@dataclass
class ControlContext:
    """Context passed to all controls."""
    repo: str
    pr_number: int
    diff: Dict[str, str] # file_path -> diff_text
    config: Dict[str, Any]
    provider: Any # GitHub/GitLab provider

@dataclass
class Finding:
    """Universal evidence format for all controls."""
    control_id: str # e.g., SEC-PR-002
    rule_id: str # e.g., SEC-PR-002.RULE-001
    severity: str # HIGH/MEDIUM/LOW
    message: str # Human-readable description
    file_path: str # Relative path
    line_number: Optional[int] = None
    evidence: Dict[str, Any] = field(default_factory=dict) # Additional structured evidence

@dataclass
class ControlSignalSet:
    """Output from a control evaluation."""
    signals: Dict[str, Any] # Signal values for policy evaluation
    findings: List[Finding] # Structured evidence for audit

class ControlBase(ABC):
    """Base class for all Phase 3 controls."""
    
    @abstractmethod
    def execute(self, context: ControlContext) -> ControlSignalSet:
        """
        Evaluate control and return signals + findings.
        
        Args:
            context: Control execution context
        
        Returns:
            ControlSignalSet with signals and findings
        """
        pass

