import uuid
from datetime import datetime
from typing import Dict, List, Optional, Literal
from pydantic import BaseModel, Field

from releasegate.policy.types import Requirement

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

class Decision(BaseModel):
    """
    The Single Source of Truth for an evaluation result.
    This object is what gets audited and enforced.
    """
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    
    release_status: Literal["ALLOWED", "BLOCKED", "CONDITIONAL", "SKIPPED"]
    
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
    
    # UX
    message: str
    reason_code: Optional[str] = None
