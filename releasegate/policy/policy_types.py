from typing import List, Optional, Any, Union, Literal, Dict
from pydantic import BaseModel, Field

class ControlSignal(BaseModel):
    """Defines a specific check within a policy."""
    signal: str # e.g., "features.total_churn", "core_risk.severity_level"
    operator: Literal[">", ">=", "<", "<=", "==", "!=", "in", "not in"]
    value: Any

class EnforcementConfig(BaseModel):
    """Defines what happens when policy triggers."""
    result: Literal["BLOCK", "WARN", "COMPLIANT"]
    message: Optional[str] = None

class EvidenceConfig(BaseModel):
    """What evidence to capture."""
    include: List[str] = []

class Policy(BaseModel):
    """
    Schema for a Compliance Policy.
    This replaces hardcoded thresholds with declarative rules.
    """
    policy_id: str = Field(..., description="Unique ID (e.g., SEC-PR-001)")
    name: str
    description: Optional[str] = None
    scope: Literal["pull_request", "commit"] = "pull_request"
    enabled: bool = True
    
    controls: List[ControlSignal]
    enforcement: EnforcementConfig
    evidence: Optional[EvidenceConfig] = None
    metadata: Optional[Dict[str, Any]] = None # Traceability: parent_policy, version, compliance, etc.

class ComplianceMetadata(BaseModel):
    """Encapsulates traceability info for a single policy/finding."""
    policy_id: str
    rule_id: str
    version: str
    effective_date: Optional[str] = None
    compliance_standards: Dict[str, str] = {}


