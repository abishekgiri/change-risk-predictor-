import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from releasegate.policy.types import Requirement
from releasegate.storage.base import resolve_tenant_id


class DecisionType(str, Enum):
    BLOCKED = "BLOCKED"
    ALLOWED = "ALLOWED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    CONDITIONAL = "CONDITIONAL"

class ExternalKeys(BaseModel):
    """External system references."""
    jira: List[str] = Field(default_factory=list)

class EnforcementTargets(BaseModel):
    """
    Destinations where the decision should be applied.
    Stored with the decision to allow retroactive enforcement.
    """
    repository: str
    pr_number: Optional[int] = None
    ref: Optional[str] = None # SHA or Branch
    github_check_name: str = "ReleaseGate"
    external: ExternalKeys = Field(default_factory=ExternalKeys)


class PolicyBinding(BaseModel):
    """
    Immutable binding to the exact policy material used to evaluate a decision.
    """
    policy_id: str
    policy_version: str
    policy_hash: str
    tenant_id: str = Field(default_factory=resolve_tenant_id)
    policy: Dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    """
    The Single Source of Truth for an evaluation result.
    This object is what gets audited and enforced.
    """
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(default_factory=resolve_tenant_id)
    timestamp: datetime
    
    release_status: DecisionType
    
    # Traceability
    matched_policies: List[str] = Field(default_factory=list)
    blocking_policies: List[str] = Field(default_factory=list) # Only popluated if BLOCKED
    policy_bundle_hash: str = "local-dev" # version/hash of policies used
    evaluation_key: Optional[str] = None # SHA256(inputs) for idempotency
    
    # Linkage
    context_id: str
    enforcement_targets: EnforcementTargets # Decouples enforcement from Context
    actor_id: Optional[str] = None
    
    # Unlocking / Enforcement
    requirements: Optional[Requirement] = None # Structured data for machines
    unlock_conditions: List[str] = Field(default_factory=list) # Human readable strings
    inputs_present: Dict[str, bool] = Field(default_factory=dict)
    input_snapshot: Dict[str, Any] = Field(default_factory=dict)
    policy_bindings: List[PolicyBinding] = Field(default_factory=list)
    
    # UX
    message: str
    reason_code: Optional[str] = None
