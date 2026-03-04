from typing import List, Optional, Any, Literal, Dict
from pydantic import BaseModel, Field, ConfigDict

class ControlSignal(BaseModel):
    """Defines a specific check within a policy."""
    model_config = ConfigDict(extra="forbid")

    signal: str # e.g., "features.total_churn", "core_risk.severity_level"
    operator: Literal[">", ">=", "<", "<=", "==", "!=", "in", "not in"]
    value: Any

class EnforcementConfig(BaseModel):
    """Defines what happens when policy triggers."""
    model_config = ConfigDict(extra="forbid")

    result: Literal["BLOCK", "WARN", "COMPLIANT"]
    message: Optional[str] = None

class EvidenceConfig(BaseModel):
    """What evidence to capture."""
    model_config = ConfigDict(extra="forbid")

    include: List[str] = []


class OverridePolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_ttl_seconds: int = 86400
    default_ttl_seconds: int = 3600
    require_expires_at: bool = True


class SeparationOfDutiesRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    left: str
    right: str
    reason_code: Optional[str] = None
    message: Optional[str] = None


class SeparationOfDutiesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    deny_self_approval: bool = True
    rules: List[SeparationOfDutiesRule] = Field(default_factory=list)

class Policy(BaseModel):
    """
    Schema for a Compliance Policy.
    This replaces hardcoded thresholds with declarative rules.
    """
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(..., description="Unique ID (e.g., SEC-PR-001)")
    version: str = Field(default="1.0.0", description="Policy version for traceability")
    name: str
    description: Optional[str] = None
    scope: Literal["pull_request", "commit"] = "pull_request"
    enabled: bool = True
    
    controls: List[ControlSignal]
    enforcement: EnforcementConfig
    evidence: Optional[EvidenceConfig] = None
    strict_fail_closed: bool = True
    overrides: Optional[OverridePolicyConfig] = None
    separation_of_duties: Optional[SeparationOfDutiesConfig] = None
    metadata: Optional[Dict[str, Any]] = None # Traceability: parent_policy, version, compliance, etc.

class ComplianceMetadata(BaseModel):
    """Encapsulates traceability info for a single policy/finding."""
    policy_id: str
    rule_id: str
    version: str
    effective_date: Optional[str] = None
    compliance_standards: Dict[str, str] = {}
