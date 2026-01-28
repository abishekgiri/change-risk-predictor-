from typing import Literal, Dict, Any, Optional, List, Union
from pydantic import BaseModel

ActionType = Literal["GITHUB_CHECK", "GITHUB_PR_COMMENT", "JIRA_COMMENT", "JIRA_TRANSITION"]

class EnforcementAction(BaseModel):
    """
    A planned action to be executed.
    """
    action_id: str
    action_type: ActionType
    target: str # e.g. PR URL, repo/pr, Jira key
    payload: Dict[str, Any]
    idempotency_key: str # Unique key to prevent duplicate execution

class EnforcementResult(BaseModel):
    """
    The result of an attempted enforcement action.
    """
    action: EnforcementAction
    status: Literal["SUCCESS", "SKIPPED", "FAILED"]
    detail: str = ""
    external_ref: Optional[str] = None # Link to the created resource (e.g. comment URL)

# --- Legacy Control Types (Maintained for backward compatibility) ---

class Finding(BaseModel):
    """
    Universally formatted finding from a control execution.
    Should be machine readable and human readable.
    """
    control_id: str = "unknown"
    description: str = ""
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    message: str = ""
    context: Dict[str, Any] = {} # Additional metadata
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    evidence: Union[List[str], Dict[str, Any]] = {}
    rule_id: str = "unknown"

class ControlSignalSet(BaseModel):
    """
    The output of a control execution.
    Contains raw signals (for policy engine) and structured findings (for humans).
    """
    signals: Dict[str, Any]
    findings: List[Finding]

class ControlContext(BaseModel):
    """
    Context passed to a legacy Control execution.
    """
    repo: str
    pr_number: int
    diff: Dict[str, Any] # simplified diff summary
    config: Dict[str, Any] # control-specific config
    provider: Optional[Any] = None # Abstract provider interface

class ControlBase:
    """
    Abstract base class for Enforcement Controls.
    """
    def execute(self, ctx: ControlContext) -> ControlSignalSet:
        raise NotImplementedError("Control must implement execute()")
