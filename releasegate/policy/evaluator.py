from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from .types import PolicyDef, Predicate, PolicyAction, Requirement
from releasegate.context.types import EvaluationContext

class PolicyResult(BaseModel):
    decision: str # "ALLOWED", "BLOCKED", "CONDITIONAL"
    matched_policies: List[str]
    blocking_policies: List[str]
    requirements: Optional[Requirement]
    message: Optional[str]

class PolicyEvaluator:
    """
    Deterministic rule engine.
    """
    
    def evaluate(self, ctx: EvaluationContext, policies: List[PolicyDef]) -> PolicyResult:
        matches = []
        
        for policy in policies:
            if self._matches(ctx, policy):
                matches.append(policy)
        
        return self._aggregate(matches)

    def _matches(self, ctx: EvaluationContext, policy: PolicyDef) -> bool:
        cond = policy.when
        
        # 1. Environment
        if cond.environment:
            if not self._check_predicate(ctx.environment, cond.environment):
                return False
                
        # 2. Signals
        if cond.signals:
            for signal_key, predicate in cond.signals.items():
                val = self._get_signal_value(ctx, signal_key)
                if not self._check_predicate(val, predicate):
                    return False
        
        # 3. Context
        if cond.context:
            for context_path, predicate in cond.context.items():
                val = self._get_context_value(ctx, context_path)
                if not self._check_predicate(val, predicate):
                    return False
                    
        return True

    def _get_signal_value(self, ctx: EvaluationContext, key: str) -> Any:
        return ctx.signals.get(key)

    def _get_context_value(self, ctx: EvaluationContext, path: str) -> Any:
        # Support dot notation: "change.lines_changed"
        parts = path.split(".")
        curr = ctx
        for part in parts:
            if hasattr(curr, part):
                curr = getattr(curr, part)
            elif isinstance(curr, dict):
                curr = curr.get(part)
            else:
                return None
        return curr

    def _check_predicate(self, value: Any, pred: Predicate) -> bool:
        if value is None:
             # Basic safety: if value missing but predicate exists, usually fails match
             # Exception: maybe 'ne' matches? For now, strict fail.
             return False

        if pred.eq is not None and value != pred.eq: return False
        if pred.ne is not None and value == pred.ne: return False
        
        # Numeric checks
        if isinstance(value, (int, float)):
            if pred.gt is not None and not (value > pred.gt): return False
            if pred.gte is not None and not (value >= pred.gte): return False
            if pred.lt is not None and not (value < pred.lt): return False
            if pred.lte is not None and not (value <= pred.lte): return False
            
        if pred.is_in is not None and value not in pred.is_in: return False
        if pred.contains is not None:
             if hasattr(value, "__contains__"):
                 if pred.contains not in value: return False
             else:
                 return False
                 
        return True

    def _aggregate(self, matches: List[PolicyDef]) -> PolicyResult:
        if not matches:
            return PolicyResult(
                decision="ALLOWED",
                matched_policies=[],
                blocking_policies=[],
                requirements=None,
                message="No policies matched."
            )
            
        # Priority sort likely already done by loader, but re-sort to be safe for message selection
        matches = sorted(matches, key=lambda p: (p.priority, p.id))
        
        matched_ids = [p.id for p in matches]
        decisions = [p.then.decision for p in matches]
        
        final_decision = "ALLOWED"
        blocking_ids = []
        
        if "BLOCKED" in decisions:
            final_decision = "BLOCKED"
            blocking_ids = [p.id for p in matches if p.then.decision == "BLOCKED"]
        elif "CONDITIONAL" in decisions:
            final_decision = "CONDITIONAL"
            
        # Merge Requirements
        final_reqs = Requirement()
        msgs = []
        
        for p in matches:
            if p.then.requires:
                final_reqs.approvals = max(final_reqs.approvals, p.then.requires.approvals)
                # Union roles
                existing = set(final_reqs.roles)
                existing.update(p.then.requires.roles)
                final_reqs.roles = sorted(list(existing))
            
            # Message selection logic: First match (highest priority) defines the primary message
            # But we might want to concatenate or just pick top. 
            # Plan says: "choose the highest priority matched policy’s message"
            if p.then.message:
                msgs.append(p.then.message)
                
        # Primary message is from top priority match
        primary_msg = msgs[0] if msgs else "Policy Evaluation Complete"

        return PolicyResult(
            decision=final_decision,
            matched_policies=matched_ids,
            blocking_policies=blocking_ids,
            requirements=final_reqs if (final_reqs.approvals > 0 or final_reqs.roles) else None,
            message=primary_msg
        )
