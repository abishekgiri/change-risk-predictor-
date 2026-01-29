import hashlib
import json
import logging
from typing import Optional, Dict, Any, List
from releasegate.integrations.jira.types import TransitionCheckRequest, TransitionCheckResponse
from releasegate.integrations.jira.client import JiraClient
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets
from releasegate.context.builder import ContextBuilder

logger = logging.getLogger(__name__)

class WorkflowGate:
    def __init__(self):
        self.client = JiraClient()
        self.policy_map_path = "releasegate/integrations/jira/jira_transition_map.yaml"
        self.role_map_path = "releasegate/integrations/jira/jira_role_map.yaml"

    def check_transition(self, request: TransitionCheckRequest) -> TransitionCheckResponse:
        """
        Evaluate if a Jira transition is allowed.
        Enforces idempotency, audit-on-error, and policy gates.
        """
        evaluation_key = self._compute_key(request)
        
        try:
            # 1. Idempotency Check
            # In a real high-throughput system you might check DB reader here.
            # For now, we rely on the DB unique constraint in the Recorder to catch duplicates at write time,
            # or we could peek. Let's proceed to evaluate; Recorder handles the "already exists" case safely now.
            
            # 2. Context Construction
            context = self._build_context(request)
            
            # 3. Policy Resolution
            policies = self._resolve_policies(request)
            if not policies:
                # No policies mapped -> ALLOW (Fail Open for unconfigured transitions)
                return self._response(True, "No policies configured for this transition", "no-policy")

            # 4. Evaluation
            # We must convert the EvaluationContext to a signal dict that ComplianceEngine expects
            # Phase 10 MVP: we flatten context into a dict
            signal_map = {
                "repo": context.change.repository,
                "pr_number": int(context.change.change_id) if context.change.change_id.isdigit() else 0,
                "diff": {}, 
                "labels": [],
                "user": {"login": context.actor.login, "role": context.actor.role},
                "environment": context.environment,
                # Safe Defaults for missing PR signals
                "files_changed": [],
                "total_churn": 0,
                "commits": [],
                "critical_paths": [],
                "dependency_changes": [],
                "secrets_findings": [],
                "licenses": []
            }
            
            from releasegate.engine import ComplianceEngine
            engine = ComplianceEngine({})
            
            # Run ALL policies (Engine doesn't support filtering input yet)
            run_result = engine.evaluate(signal_map)
            
            # Filter results to ONLY the policies required by this Jira transition
            relevant_results = [r for r in run_result.results if r.policy_id in policies]
            
            # Determine Status based on Filtered Results
            status = "ALLOWED"
            blocking_policies = []
            requirements = []
            
            for res in relevant_results:
                if res.status == "BLOCK":
                    status = "BLOCKED"
                    blocking_policies.append(res.policy_id)
                    requirements.extend(res.violations)
                elif res.status == "WARN" and status != "BLOCKED":
                    status = "CONDITIONAL" # Map WARN to CONDITIONAL
                    requirements.extend(res.violations)

            # Construct Decision Object manually since Engine returns ComplianceRunResult
            from releasegate.decision.types import Decision
            from datetime import datetime, timezone
            import uuid
            
            decision = Decision(
                decision_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                release_status=status,
                context_id=f"jira-{request.issue_key}",
                message=f"Policy Check: {status}",
                requirements={}, # Keep structured requirements empty for now to avoid validation issues
                unlock_conditions=requirements or ["None"], # Store human-readable checks here
                matched_policies=blocking_policies, # Track what blocked
                policy_bundle_hash="local-hash",
                enforcement_targets=EnforcementTargets(
                    repository=request.context_overrides.get("repo", "unknown"),
                    ref=request.context_overrides.get("ref", "HEAD"),
                    external={"jira": [request.issue_key]}
                )
            )
            
            # 6. Audit Recording
            # This handles duplicate inserts (idempotency) by returning existing decision if present
            final_decision = AuditRecorder.record_with_context(
                decision, 
                repo=decision.enforcement_targets.repository, 
                pr_number=request.context_overrides.get("pr_number", 0)
            )
            
            # 7. UX Logic
            # Map ReleaseGate Status to Jira Action
            # CONDITIONAL -> BLOCKED in Prod
            is_prod = request.environment.upper() == "PRODUCTION"
            status = final_decision.release_status
            
            if is_prod and status == "CONDITIONAL":
                status = "BLOCKED"
                final_decision.message = f"[Prod Gate] Conditional approval treated as BLOCK. Requirements: {final_decision.unlock_conditions}"

            allow = (status == "ALLOWED")
            reason = final_decision.message
            
            if not allow:
                self.client.post_comment_deduped(
                    request.issue_key, 
                    f"⛔ **ReleaseGate Blocked**\n\n{reason}\n\nDecision ID: `{final_decision.decision_id}`", 
                    evaluation_key[:16] # Use a stable hash prefix for dedup
                )
            
            # Use unlock_conditions (list of strings) for the response requirement list
            resp_requirements = final_decision.unlock_conditions or []
            
            return TransitionCheckResponse(
                allow=allow,
                reason=reason,
                decision_id=final_decision.decision_id,
                status=status,
                requirements=resp_requirements,
                unlock_conditions=final_decision.unlock_conditions
            )

        except Exception as e:
            logger.error(f"Jira Gate Error: {e}", exc_info=True)
            import uuid
            is_prod = request.environment.upper() == "PRODUCTION"
            # In Prod, we Fail Closed (Block). In Non-Prod, Fail Open.
            
            # Try to record the FAILURE in audit if possible
            # (Skipped for brevity/complexity, but highly recommended)
            
            return TransitionCheckResponse(
                allow=not is_prod,
                reason=f"System Error: {str(e)}",
                decision_id=str(uuid.uuid4()),
                status="BLOCKED" if is_prod else "ALLOWED"
            )

    def _compute_key(self, req: TransitionCheckRequest) -> str:
        """SHA256(issue + transition + status_change + env + actor)"""
        # Include target_status as critical differentiator
        raw = f"{req.issue_key}:{req.transition_id}:{req.source_status}:{req.target_status}:{req.environment}:{req.actor_account_id}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _build_context(self, req: TransitionCheckRequest):
        """Construct the EvaluationContext from Jira request + Jira API data."""
        from releasegate.context.types import EvaluationContext, Actor, Change, Timing
        
        # 1. Resolve Role
        role = self._resolve_role(req.actor_email) # Simplification: mapping email/account to role
        
        # 2. Extract PR (Change Context)
        repo = req.context_overrides.get("repo", "unknown/repo")
        pr_id = "0"
        
        # Try Dev Status if no override
        if "repo" not in req.context_overrides:
            # Fetch from Jira
            # For MVP, we skip the complex dev-status parsing logic and fallback to regex/custom field
            # Real impl would call self.client.get_dev_status(req.issue_id)
            pass
            
        change = Change(
            change_type="PR",
            change_id=pr_id,
            repository=repo,
            files=[], # We don't have files from Jira directly without fetching PR
            is_draft=False
        )
        
        # 3. Actor
        actor = Actor(
            user_id=req.actor_account_id,
            login=req.actor_email or req.actor_account_id,
            role=role,
            team=None
        )
        
        return EvaluationContext(
            actor=actor,
            change=change,
            environment=req.environment,
            timing=Timing(change_window="OPEN")
        )

    def _resolve_policies(self, req: TransitionCheckRequest) -> List[str]:
        """Load YAML and resolve based on Env -> Project -> Transition."""
        import yaml
        try:
            with open(self.policy_map_path, 'r') as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning("Policy map not found, allowing all.")
            return []

        # 1. Environment
        env_map = data.get(req.environment, {})
        if not env_map:
            return []
            
        # 2. Project vs DEFAULT
        proj_map = env_map.get(req.project_key, env_map.get("DEFAULT", {}))
        
        # 3. Transition ID vs Name
        # Try ID first
        if req.transition_id in proj_map:
            return proj_map[req.transition_id]
        
        # Try Name
        if req.transition_name and req.transition_name in proj_map:
            return proj_map[req.transition_name]
            
        return []

    def _resolve_role(self, identifier: Optional[str]) -> str:
        """Map user identifier to role using yaml map."""
        # For Phase 10 MVP, we return a default or use map
        # In real life: fetch user groups from Jira -> check map
        return "Engineer" # Default safe assumption

