from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union, Literal

class Predicate(BaseModel):
    """
    Structured operators for conditions.
    Avoids string parsing ">=60".
    """
    eq: Optional[Any] = None
    ne: Optional[Any] = None
    gt: Optional[Union[int, float]] = None
    gte: Optional[Union[int, float]] = None
    lt: Optional[Union[int, float]] = None
    lte: Optional[Union[int, float]] = None
    is_in: Optional[List[Any]] = Field(default=None, alias="in")
    contains: Optional[Any] = None

class PolicyConditions(BaseModel):
    """
    Conditions that must match for the policy to apply.
    """
    environment: Optional[Predicate] = None
    signals: Optional[Dict[str, Predicate]] = None
    context: Optional[Dict[str, Predicate]] = None

class Requirement(BaseModel):
    """
    What is required if this policy triggers.
    """
    approvals: int = 0
    roles: List[str] = Field(default_factory=list)

class PolicyAction(BaseModel):
    """
    The outcome of the policy.
    """
    decision: Literal["ALLOWED", "BLOCKED", "CONDITIONAL"]
    requires: Optional[Requirement] = None
    message: str

class PolicyDef(BaseModel):
    """
    A single policy rule definition.
    """
    id: str
    description: str
    priority: int = 100 # Lower number = higher priority
    when: PolicyConditions
    then: PolicyAction
    
    # Metadata for traceability
    source_file: Optional[str] = None
