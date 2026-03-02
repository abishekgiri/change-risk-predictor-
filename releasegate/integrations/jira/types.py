from pydantic import BaseModel, Field, ConfigDict, AliasChoices
from typing import Optional, List, Dict, Any, Literal

class TransitionCheckRequest(BaseModel):
    """
    Request payload from Jira Webhook or Automation.
    Represents an attempt to transition an issue.
    """
    issue_key: str = Field(..., description="Jira Issue Key e.g. PROJ-123")
    
    # Transition Details (for Idempotency & Routing)
    transition_id: str = Field(
        ...,
        validation_alias=AliasChoices("transition_id", "transitionId"),
        description="ID of the transition being attempted",
    )
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
    tenant_id: Optional[str] = Field(None, description="Tenant/organization identity for multi-tenant isolation")
    
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
    decision_id: str = Field(..., description="ReleaseGate deterministic decision identifier")
    status: Literal["ALLOWED", "CONDITIONAL", "BLOCKED", "SKIPPED", "ERROR"] = Field(..., description="ReleaseGate Status")
    reason_code: Optional[str] = Field(None, description="Machine-readable reason code for the decision")
    policy_hash: Optional[str] = Field(None, description="Hash fingerprint of compiled policy bundle")
    tenant_id: Optional[str] = Field(None, description="Tenant/organization identity")
    
    requirements: List[str] = Field(default_factory=list, description="List of unsatisfied requirements")
    unlock_conditions: List[str] = Field(default_factory=list, description="Human readable unlock instructions")
    
    model_config = ConfigDict(extra="ignore")


class TransitionAuthorizeRequest(BaseModel):
    """
    Authorization payload used by Jira protected-state validators.
    """
    issue_key: str = Field(..., description="Jira Issue Key e.g. PROJ-123")
    transition_id: str = Field(
        ...,
        validation_alias=AliasChoices("transition_id", "transitionId"),
        description="ID of the transition being attempted",
    )
    source_status: str = Field(..., description="Current status of the issue")
    target_status: str = Field(..., description="Destination status of the issue")
    actor_account_id: str = Field(..., description="Jira Account ID of the user initiating transition")
    environment: Optional[str] = Field(None, description="Target environment (PRODUCTION, STAGING, etc.)")
    project_key: Optional[str] = Field(None, description="Project Key e.g. PROJ")
    tenant_id: Optional[str] = Field(None, description="Tenant/organization identity for multi-tenant isolation")
    releasegate_decision_id: Optional[str] = Field(
        None,
        min_length=1,
        description="Decision ID returned by /integrations/jira/transition/check",
    )
    request_id: Optional[str] = Field(
        None,
        description="Stable request identifier to make decision consumption idempotent",
    )

    model_config = ConfigDict(extra="ignore")


class TransitionAuthorizeResponse(BaseModel):
    """
    Authorization response consumed by Jira validators.
    """
    allow: bool = Field(..., description="Whether to allow the transition")
    decision_id: Optional[str] = Field(None, description="Decision ID used for authorization")
    reason_code: Optional[str] = Field(None, description="Machine-readable reason code")
    message: Optional[str] = Field(None, description="Human-readable reason")
    tenant_id: Optional[str] = Field(None, description="Tenant/organization identity")

    model_config = ConfigDict(extra="ignore")


class DecisionApprovalRequest(BaseModel):
    """
    Submit an approval against the current decision approval scope.
    """

    tenant_id: Optional[str] = Field(None, description="Tenant/organization identity")
    approver_actor_id: Optional[str] = Field(None, description="Approver identity (defaults to authenticated principal)")
    approver_role: Optional[str] = Field(None, description="Approver role (e.g., security, em, ops)")
    approval_group: Optional[str] = Field(None, description="CAB group name this approval should satisfy")
    justification: Dict[str, Any] = Field(default_factory=dict, description="Structured approval justification payload")
    request_id: Optional[str] = Field(None, description="Idempotency token for approval submission")

    model_config = ConfigDict(extra="ignore")


class DecisionApprovalResponse(BaseModel):
    """
    Approval submission response.
    """

    ok: bool = Field(..., description="Whether the approval was accepted")
    tenant_id: str = Field(..., description="Tenant identity")
    decision_id: str = Field(..., description="Decision being approved")
    approval_id: str = Field(..., description="Stored approval identifier")
    approval_scope_hash: str = Field(..., description="Scope hash this approval is bound to")
    approver_actor: str = Field(..., description="Approver identity")
    approver_role: Optional[str] = Field(None, description="Normalized approver role")
    approval_group: Optional[str] = Field(None, description="Normalized approval group")
    created_at: str = Field(..., description="Approval timestamp")

    model_config = ConfigDict(extra="ignore")
