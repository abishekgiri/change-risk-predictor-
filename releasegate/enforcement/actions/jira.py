from typing import Set, Any
from releasegate.enforcement.base import Enforcer
from releasegate.enforcement.types import EnforcementAction, EnforcementResult, ActionType

class JiraEnforcer(Enforcer):
    """
    Simulates interactions with Jira API.
    """
    
    def supported_actions(self) -> Set[ActionType]:
        return {"JIRA_COMMENT", "JIRA_TRANSITION"}

    def execute(self, action: EnforcementAction) -> EnforcementResult:
        print(f"[Jira Mock] Executing {action.action_type} on {action.target}")
        print(f"[Jira Mock] Payload: {action.payload}")
        
        if action.action_type == "JIRA_COMMENT":
            print(f"[Jira Mock] POST /issue/{action.target}/comment")
            return EnforcementResult(
                action=action,
                status="SUCCESS",
                detail="Simulated Comment added",
                external_ref="https://jira.example.com/issue/123/comment/456"
            )
            
        return EnforcementResult(action=action, status="FAILED", detail="Unsupported mock action")
