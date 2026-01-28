import hashlib
from typing import List
from releasegate.decision.types import Decision
from releasegate.context.types import EvaluationContext
from .types import EnforcementAction, ActionType

class EnforcementPlanner:
    """
    Deterministic function: Decision -> List[Action]
    Now fully decoupled from EvaluationContext.
    """
    
    @staticmethod
    def plan(decision: Decision) -> List[EnforcementAction]:
        actions = []
        targets = decision.enforcement_targets
        
        # 1. GitHub Status Check (Always)
        gh_status = "success"
        gh_desc = "Policy Check Passed"
        
        if decision.release_status == "BLOCKED":
            gh_status = "failure"
            gh_desc = f"BLOCKED: {decision.message}"
        elif decision.release_status == "CONDITIONAL":
            gh_status = "neutral" 
            gh_desc = "Waiting for requirements"
        
        # Ensure we have a ref/SHA to attach check to
        ref = targets.ref or "HEAD"
        
        actions.append(EnforcementPlanner._create_action(
            decision,
            "GITHUB_CHECK",
            targets.repository, 
            {
                "check_name": targets.github_check_name,
                "head_sha": ref,
                "status": "completed",
                "conclusion": gh_status,
                "output": {
                    "title": f"{targets.github_check_name} Policy Check",
                    "summary": decision.message,
                    "text": _format_text(decision)
                }
            }
        ))
        
        # 2. Jira Comment (If Blocked or Conditional)
        if decision.release_status in ["BLOCKED", "CONDITIONAL"]:
             for jira_key in targets.external.jira:
                 actions.append(EnforcementPlanner._create_action(
                     decision,
                     "JIRA_COMMENT",
                     jira_key,
                     {"body": f"[ReleaseGate] {decision.release_status}: {decision.message}"}
                 ))

        return actions

    @staticmethod
    def _create_action(decision: Decision, action_type: ActionType, target: str, payload: dict) -> EnforcementAction:
        # Idempotency Key: decision_id + action_type + target
        # Ensures for a given decision, we only execute this specific action once
        raw_key = f"{decision.decision_id}:{action_type}:{target}"
        idempotency_key = hashlib.sha256(raw_key.encode()).hexdigest()
        
        return EnforcementAction(
            action_id=idempotency_key[:12],
            action_type=action_type,
            target=target,
            payload=payload,
            idempotency_key=idempotency_key
        )

def _format_text(d: Decision) -> str:
    text = f"Status: {d.release_status}\n\n"
    if d.unlock_conditions:
        text += "Requirements:\n"
        for c in d.unlock_conditions:
            text += f"- {c}\n"
    return text
