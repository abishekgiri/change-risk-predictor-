from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any, Literal

class TransitionCheckRequest(BaseModel):
    """
    Request payload from Jira Webhook or Automation.
    Represents an attempt to transition an issue.
    """
    issue_key: str = Field(..., description="Jira Issue Key e.g. PROJ-123")
    
    # Transition Details (for Idempotency & Routing)
    transition_id: str = Field(..., description="ID of the transition being attempted")
    transition_name: Optional[str] = Field(None, description="Human readable name of transition")
    source_status: str = Field(..., description="Current status of the issue")
    target_status: str = Field(..., description="Destination status of the issue")
    
    # Identity
    actor_account_id: str = Field(..., description="Jira Account ID of the user initiating transition")
    actor_email: Optional[str] = Field(None, description="Fallback email if available")
    
    # Context
    environment: str = Field(..., description="Target environment (PRODUCTION, STAGING, etc.)")
    project_key: str = Field(..., description="Project Key e.g. PROJ")
    issue_type: str = Field(..., description="Issue Type e.g. Story, Bug")
    
    # Overrides (Optional)
    context_overrides: Dict[str, Any] = Field(default_factory=dict, description="Manual context like repo/pr")

    model_config = ConfigDict(extra="ignore")

class TransitionCheckResponse(BaseModel):
    """
    Response consumed by Jira Automation.
    """
    allow: bool = Field(..., description="Whether to allow the transition")
    reason: str = Field(..., description="Short explanation for the decision")
    
    # Full Metadata
    decision_id: str = Field(..., description="ReleaseGate Decision UUID")
    status: Literal["ALLOWED", "CONDITIONAL", "BLOCKED"] = Field(..., description="ReleaseGate Status")
    
    requirements: List[str] = Field(default_factory=list, description="List of unsatisfied requirements")
    unlock_conditions: List[str] = Field(default_factory=list, description="Human readable unlock instructions")
    
    model_config = ConfigDict(extra="ignore")
