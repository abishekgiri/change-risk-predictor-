from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Literal
from datetime import datetime, timezone
import uuid

class Actor(BaseModel):
    """The entity initiating the change."""
    user_id: str = Field(..., description="Unique identifier for the actor")
    login: str = Field(..., description="GitHub login or similar")
    role: str = Field(..., description="Role of the actor e.g. 'Engineer', 'Admin'")
    team: Optional[str] = Field(None, description="Team the actor belongs to")
    meta: Dict[str, str] = Field(default_factory=dict)

class Change(BaseModel):
    """The modification being evaluated."""
    change_type: Literal["PR", "HOTFIX", "CONFIG"] = Field(..., description="Type of change")
    change_id: str = Field(..., description="Unique ID e.g. PR number or Commit SHA")
    repository: str = Field(..., description="Repository name")
    files: List[str] = Field(default_factory=list, description="List of modified files")
    lines_changed: int = Field(0, description="Total lines added/removed")
    
    # Enrichment fields
    base_branch: Optional[str] = None
    head_sha: Optional[str] = None
    author_login: Optional[str] = None
    labels: List[str] = Field(default_factory=list)
    is_draft: bool = False
    
    title: Optional[str] = None
    description: Optional[str] = None

class Timing(BaseModel):
    """Temporal context for the change."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    change_window: Literal["OPEN", "CLOSED", "EMERGENCY_ONLY"] = Field("OPEN", description="Result of change freeze check")

class EvaluationContext(BaseModel):
    """
    The complete context required for a policy decision.
    'No context = no decision.'
    """
    context_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Stable ID for audit")
    actor: Actor
    change: Change
    environment: Literal["PRODUCTION", "STAGING", "DEV", "UNKNOWN"] = Field("UNKNOWN", description="Target environment")
    timing: Timing
    signals: Dict[str, float] = Field(default_factory=dict, description="Pre-computed signals (risk, churn, etc.)")
    
    # Allow arbitrary lookups for policy engine
    
    # Allow arbitrary lookups for policy engine
    model_config = ConfigDict(extra="forbid")
