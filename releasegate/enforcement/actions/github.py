from typing import Set, Any
from releasegate.enforcement.base import Enforcer
from releasegate.enforcement.types import EnforcementAction, EnforcementResult, ActionType

class GitHubEnforcer(Enforcer):
    """
    Simulates interactions with GitHub Checks API.
    """
    
    def supported_actions(self) -> Set[ActionType]:
        return {"GITHUB_CHECK", "GITHUB_PR_COMMENT"}

    def execute(self, action: EnforcementAction) -> EnforcementResult:
        print(f"[GitHub Mock] Executing {action.action_type} on {action.target}")
        print(f"[GitHub Mock] Payload: {action.payload}")
        
        # Simulate Check Run creation
        if action.action_type == "GITHUB_CHECK":
            print(f"[GitHub Mock] POST /repos/{action.target}/check-runs")
            return EnforcementResult(
                action=action,
                status="SUCCESS",
                detail="Simulated Check Run created",
                external_ref="https://github.com/check/123"
            )
            
        return EnforcementResult(action=action, status="FAILED", detail="Unsupported mock action")
