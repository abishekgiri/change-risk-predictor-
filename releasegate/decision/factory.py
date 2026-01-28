from datetime import datetime, timezone
import hashlib
from typing import List

from releasegate.context.types import EvaluationContext
from releasegate.policy.evaluator import PolicyResult
from releasegate.policy.types import PolicyDef
from .types import Decision, EnforcementTargets, ExternalKeys

class DecisionFactory:
    """
    Converts raw policy evaluation results into a canonical Decision object.
    Handling logic for formatting and defaults.
    """
    
    @staticmethod
    def create(ctx: EvaluationContext, result: PolicyResult, policies: List[PolicyDef]) -> Decision:
        now = datetime.now(timezone.utc)
        
        # 1. Compute Bundle Hash (Simple trace of active policies)
        # In prod this might be a git commit SHA or signed bundle ID
        policy_ids = sorted([p.id for p in policies])
        bundle_hash = hashlib.sha256(",".join(policy_ids).encode()).hexdigest()[:8]
        
        # 2. Filtering
        blocking_policies = result.blocking_policies if result.decision == "BLOCKED" else []
        
        # 3. Humanize Requirements
        conditions = []
        if result.requirements:
            if result.requirements.approvals > 0:
                conditions.append(f"{result.requirements.approvals} approval(s) required")
            
            for role in result.requirements.roles:
                conditions.append(f"Approval required from role: {role}")

        # 4. Build Enforcement Targets
        # Try to parse PR number if available
        pr_num = None
        if ctx.change.change_type == "PR":
            try:
                pr_num = int(ctx.change.change_id)
            except:
                pass
                
        targets = EnforcementTargets(
            repository=ctx.change.repository,
            pr_number=pr_num,
            ref=ctx.change.head_sha or "HEAD",
            external=ExternalKeys(
                # Future: Extract jira keys from Change object
                jira=[] 
            )
        )
        
        # 5. Compute Evaluation Key (Idempotency)
        # sha256(repo + pr + head_sha + policy_bundle_hash + environment)
        # Note: Environment is in Context
        raw_key = f"{ctx.change.repository}:{ctx.change.change_id}:{ctx.change.head_sha or 'HEAD'}:{bundle_hash}:{ctx.environment}"
        eval_key = hashlib.sha256(raw_key.encode()).hexdigest()
        
        return Decision(
            timestamp=now,
            release_status=result.decision,
            matched_policies=result.matched_policies,
            blocking_policies=blocking_policies,
            policy_bundle_hash=bundle_hash,
            evaluation_key=eval_key,
            context_id=ctx.context_id,
            enforcement_targets=targets,
            requirements=result.requirements,
            unlock_conditions=conditions,
            message=result.message or "No policy message provided"
        )
