import sqlite3
from typing import List, Dict, Type
from releasegate.config import DB_PATH
from releasegate.enforcement.types import EnforcementAction, EnforcementResult, ActionType
from releasegate.enforcement.base import Enforcer
from releasegate.enforcement.actions.github import GitHubEnforcer
from releasegate.enforcement.actions.jira import JiraEnforcer

class EnforcementRunner:
    def __init__(self):
        self._enforcers: Dict[ActionType, Enforcer] = {}
        self._register_default_enforcers()

    def _register_default_enforcers(self):
        # In a real app, use dependency injection or registry
        self.register_enforcer(GitHubEnforcer())
        self.register_enforcer(JiraEnforcer())

    def register_enforcer(self, enforcer: Enforcer):
        for action_type in enforcer.supported_actions():
            self._enforcers[action_type] = enforcer

    def run(self, actions: List[EnforcementAction]) -> List[EnforcementResult]:
        results = []
        for action in actions:
            result = self._process_action(action)
            results.append(result)
        return results

    def _process_action(self, action: EnforcementAction) -> EnforcementResult:
        # 1. Check Idempotency
        if self._is_already_executed(action.idempotency_key):
             return EnforcementResult(
                 action=action,
                 status="SKIPPED",
                 detail="Action already executed (idempotent)"
             )

        # 2. Lookup Enforcer
        enforcer = self._enforcers.get(action.action_type)
        if not enforcer:
            return EnforcementResult(
                action=action,
                status="FAILED",
                detail=f"No enforcer found for {action.action_type}"
            )

        # 3. Execute
        try:
            result = enforcer.execute(action)
            self._record_execution(action, result)
            return result
        except Exception as e:
            err_result = EnforcementResult(
                action=action,
                status="FAILED",
                detail=f"Execution error: {str(e)}"
            )
            self._record_execution(action, err_result)
            return err_result

    def _is_already_executed(self, key: str) -> bool:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM enforcement_events WHERE idempotency_key = ?", (key,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists

    def _record_execution(self, action: EnforcementAction, result: EnforcementResult):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO enforcement_events (idempotency_key, decision_id, action_type, target, status, detail)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            action.idempotency_key,
            # We don't have decision_id easily here without passing it down, 
            # but idempotency_key is derived from it. 
            # Ideally action should carry a decision_id ref, but for now we trust the flow.
            # Let's extract from key if possible or just use action_id
            action.action_id, 
            action.action_type,
            action.target,
            result.status,
            result.detail
        ))
        conn.commit()
        conn.close()
