import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from releasegate.integrations.jira.types import TransitionCheckRequest, TransitionCheckResponse
from releasegate.integrations.jira.client import JiraClient
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets, DecisionType
from releasegate.policy.loader import PolicyLoader
from releasegate.observability.internal_metrics import incr

logger = logging.getLogger(__name__)

class WorkflowGate:
    def __init__(self):
        self.client = JiraClient()
        self.policy_map_path = "releasegate/integrations/jira/jira_transition_map.yaml"
        self.role_map_path = "releasegate/integrations/jira/jira_role_map.yaml"
        self.strict_mode = os.getenv("RELEASEGATE_STRICT_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
        self._policy_map_cache: Optional[Dict[str, Any]] = None
        self._policy_hash_cache: Optional[str] = None

    def check_transition(self, request: TransitionCheckRequest) -> TransitionCheckResponse:
        """
        Evaluate if a Jira transition is allowed.
        Enforces idempotency, audit-on-error, and policy gates.
        """
        evaluation_key = self._compute_key(request)
        repo, pr_number = self._repo_and_pr(request)
        incr("transitions_evaluated")

        # Override path (fail-open with ledger)
        if request.context_overrides.get("override") is True:
            override_reason = request.context_overrides.get("override_reason", "override")
            decision = self._build_decision(
                request,
                release_status=DecisionType.ALLOWED,
                message=f"Override applied: {override_reason}",
                evaluation_key=f"{evaluation_key}:override",
                unlock_conditions=[override_reason],
                reason_code="OVERRIDE_APPLIED",
                inputs_present={"releasegate_risk": True, "override_requested": True},
                policy_hash=self._current_policy_hash(),
            )
            final_decision = AuditRecorder.record_with_context(
                decision,
                repo=repo,
                pr_number=pr_number,
            )
            try:
                from releasegate.audit.overrides import record_override
                record_override(
                    repo=repo,
                    pr_number=pr_number,
                    issue_key=request.issue_key,
                    decision_id=final_decision.decision_id,
                    actor=request.actor_email or request.actor_account_id,
                    reason=override_reason
                )
            except Exception as e:
                logger.warning(f"Override ledger write failed: {e}")
            logger.info(
                "ReleaseGate transition decision=%s status=%s issue=%s decision_id=%s",
                "override",
                "ALLOWED",
                request.issue_key,
                final_decision.decision_id,
            )
            incr("overrides_used")
            return TransitionCheckResponse(
                allow=True,
                reason=final_decision.message,
                decision_id=final_decision.decision_id,
                status="ALLOWED",
                unlock_conditions=final_decision.unlock_conditions,
                policy_hash=final_decision.policy_bundle_hash,
            )

        # Fail-open explicitly with an audited SKIPPED decision when Jira risk metadata is missing.
        risk_meta = self.client.get_issue_property(request.issue_key, "releasegate_risk")
        if self._is_missing_risk_metadata(risk_meta):
            missing_status = DecisionType.BLOCKED if self.strict_mode else DecisionType.SKIPPED
            missing_reason = (
                "BLOCKED: missing issue property `releasegate_risk` (strict mode)"
                if self.strict_mode
                else "SKIPPED: missing issue property `releasegate_risk`"
            )
            skipped = self._build_decision(
                request,
                release_status=missing_status,
                message=missing_reason,
                evaluation_key=f"{evaluation_key}:missing-risk",
                unlock_conditions=[
                    "Run GitHub PR classification to attach `releasegate_risk` on this issue."
                ],
                reason_code="MISSING_RISK_METADATA_STRICT" if self.strict_mode else "MISSING_RISK_METADATA",
                inputs_present={"releasegate_risk": False},
                policy_hash=self._current_policy_hash(),
            )
            final_skipped = AuditRecorder.record_with_context(
                skipped,
                repo=repo,
                pr_number=pr_number,
            )
            logger.info(
                "ReleaseGate transition decision=%s status=%s issue=%s decision_id=%s",
                "missing-risk",
                final_skipped.release_status,
                request.issue_key,
                final_skipped.decision_id,
            )
            if final_skipped.release_status == DecisionType.SKIPPED:
                incr("skipped_count")
            if final_skipped.release_status == DecisionType.BLOCKED:
                incr("transitions_blocked")
            return TransitionCheckResponse(
                allow=final_skipped.release_status != DecisionType.BLOCKED,
                reason=final_skipped.message,
                decision_id=final_skipped.decision_id,
                status=final_skipped.release_status.value,
                requirements=["Missing `releasegate_risk` metadata"],
                unlock_conditions=final_skipped.unlock_conditions,
                policy_hash=final_skipped.policy_bundle_hash,
            )
        
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
                # No policies mapped -> explicit audited skip (Fail Open, not silent)
                skipped = self._build_decision(
                    request,
                    release_status=DecisionType.SKIPPED,
                    message="SKIPPED: no policies configured for this transition",
                    evaluation_key=f"{evaluation_key}:no-policy",
                    unlock_conditions=["Map this transition to one or more policy IDs."],
                    reason_code="NO_POLICIES_MAPPED",
                    inputs_present={"releasegate_risk": True},
                    policy_hash=self._current_policy_hash(),
                )
                final_skipped = AuditRecorder.record_with_context(
                    skipped,
                    repo=repo,
                    pr_number=pr_number,
                )
                logger.info(
                    "ReleaseGate transition decision=%s status=%s issue=%s decision_id=%s",
                    "no-policy",
                    "SKIPPED",
                    request.issue_key,
                    final_skipped.decision_id,
                )
                incr("skipped_count")
                return TransitionCheckResponse(
                    allow=True,
                    reason=final_skipped.message,
                    decision_id=final_skipped.decision_id,
                    status="SKIPPED",
                    unlock_conditions=final_skipped.unlock_conditions,
                    policy_hash=final_skipped.policy_bundle_hash,
                )

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
            loaded_policy_ids = {r.policy_id for r in run_result.results}
            unresolved_policy_ids = sorted(set(policies) - loaded_policy_ids)
            meta = run_result.metadata if isinstance(run_result.metadata, dict) else {}
            meta_policy_hash = meta.get("policy_hash")
            policy_hash = meta_policy_hash if isinstance(meta_policy_hash, str) and meta_policy_hash else self._current_policy_hash()

            if unresolved_policy_ids:
                invalid = self._build_decision(
                    request,
                    release_status=DecisionType.SKIPPED,
                    message=f"SKIPPED: invalid policy references: {', '.join(unresolved_policy_ids)}",
                    evaluation_key=f"{evaluation_key}:invalid-policy",
                    unlock_conditions=["Fix Jira transition policy mapping to compiled policy IDs."],
                    reason_code="INVALID_POLICY_REFERENCE",
                    inputs_present={"releasegate_risk": True},
                    policy_hash=policy_hash,
                )
                final_invalid = AuditRecorder.record_with_context(
                    invalid,
                    repo=repo,
                    pr_number=pr_number,
                )
                logger.info(
                    "ReleaseGate transition decision=%s status=%s issue=%s decision_id=%s policy_hash=%s",
                    "invalid-policy",
                    final_invalid.release_status,
                    request.issue_key,
                    final_invalid.decision_id,
                    final_invalid.policy_bundle_hash,
                )
                incr("skipped_count")
                return TransitionCheckResponse(
                    allow=True,
                    reason=final_invalid.message,
                    decision_id=final_invalid.decision_id,
                    status=final_invalid.release_status.value,
                    unlock_conditions=final_invalid.unlock_conditions,
                    policy_hash=final_invalid.policy_bundle_hash,
                )
            
            status, blocking_policies, requirements = self._evaluate_policy_results(relevant_results)

            # Construct Decision Object manually since Engine returns ComplianceRunResult
            decision = self._build_decision(
                request,
                release_status=status,
                message=f"Policy Check ({request.source_status} -> {request.target_status}): {status.value}",
                evaluation_key=f"{evaluation_key}:evaluated",
                unlock_conditions=requirements or ["None"],
                matched_policies=blocking_policies, # Track what blocked
                reason_code=self._reason_code_for_status(status.value),
                inputs_present={"releasegate_risk": True},
                policy_hash=policy_hash,
            )
            
            # 6. Audit Recording
            # This handles duplicate inserts (idempotency) by returning existing decision if present
            final_decision = AuditRecorder.record_with_context(
                decision, 
                repo=repo, 
                pr_number=pr_number
            )
            
            # 7. UX Logic
            # Map ReleaseGate Status to Jira Action
            # CONDITIONAL -> BLOCKED in Prod
            is_prod = request.environment.upper() == "PRODUCTION"
            status = final_decision.release_status
            
            if is_prod and status == DecisionType.CONDITIONAL:
                status = DecisionType.BLOCKED
                final_decision.message = f"[Prod Gate] Conditional approval treated as BLOCK. Requirements: {final_decision.unlock_conditions}"

            allow = status in {DecisionType.ALLOWED, DecisionType.SKIPPED}
            reason = final_decision.message
            
            if not allow:
                self.client.post_comment_deduped(
                    request.issue_key, 
                    f"⛔ **ReleaseGate Blocked**\n\n{reason}\n\nDecision ID: `{final_decision.decision_id}`", 
                    evaluation_key[:16] # Use a stable hash prefix for dedup
                )
            
            # Use unlock_conditions (list of strings) for the response requirement list
            resp_requirements = final_decision.unlock_conditions or []
            logger.info(
                "ReleaseGate transition decision=%s status=%s issue=%s decision_id=%s",
                "evaluated",
                status,
                request.issue_key,
                final_decision.decision_id,
            )
            if status == DecisionType.BLOCKED:
                incr("transitions_blocked")
            if status == DecisionType.SKIPPED:
                incr("skipped_count")
            
            return TransitionCheckResponse(
                allow=allow,
                reason=reason,
                decision_id=final_decision.decision_id,
                status=status.value,
                requirements=resp_requirements,
                unlock_conditions=final_decision.unlock_conditions,
                policy_hash=final_decision.policy_bundle_hash,
            )

        except Exception as e:
            logger.error(f"Jira Gate Error: {e}", exc_info=True)
            is_prod = request.environment.upper() == "PRODUCTION"
            fallback_status = DecisionType.ERROR
            fallback_decision = self._build_decision(
                request,
                release_status=fallback_status,
                message=f"System Error: {str(e)}",
                evaluation_key=f"{evaluation_key}:error",
                unlock_conditions=["Retry transition after resolving ReleaseGate system errors."],
                reason_code="SYSTEM_ERROR",
                inputs_present={"releasegate_risk": False},
                policy_hash=self._current_policy_hash(),
            )
            final_fallback = AuditRecorder.record_with_context(
                fallback_decision,
                repo=repo,
                pr_number=pr_number,
            )
            logger.info(
                "ReleaseGate transition decision=%s status=%s issue=%s decision_id=%s",
                "system-error",
                fallback_status,
                request.issue_key,
                final_fallback.decision_id,
            )
            incr("transitions_error")
            if is_prod:
                incr("transitions_blocked")
            return TransitionCheckResponse(
                allow=not is_prod,
                reason=final_fallback.message,
                decision_id=final_fallback.decision_id,
                status=fallback_status.value,
                policy_hash=final_fallback.policy_bundle_hash,
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
        """Resolve policies based on Env -> Project -> Transition."""
        data = self._load_policy_map()
        if not data:
            logger.warning("Policy map not found or empty, allowing all.")
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

    def _load_policy_map(self) -> Dict[str, Any]:
        import yaml

        if self._policy_map_cache is not None:
            return self._policy_map_cache

        try:
            with open(self.policy_map_path, 'r') as f:
                data = yaml.safe_load(f) or {}
                self._policy_map_cache = data
                return data
        except FileNotFoundError:
            return {}

    def _current_policy_hash(self) -> str:
        if self._policy_hash_cache:
            return self._policy_hash_cache

        loader = PolicyLoader(policy_dir="releasegate/policy/compiled", schema="compiled", strict=False)
        try:
            policies = loader.load_all()
        except Exception:
            policies = []

        canonical = []
        for policy in sorted(policies, key=lambda p: getattr(p, "policy_id", "")):
            if hasattr(policy, "model_dump"):
                canonical.append(policy.model_dump(mode="json", exclude_none=True))
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        self._policy_hash_cache = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self._policy_hash_cache

    def _resolve_role(self, identifier: Optional[str]) -> str:
        """Map user identifier to role using yaml map."""
        # For Phase 10 MVP, we return a default or use map
        # In real life: fetch user groups from Jira -> check map
        return "Engineer" # Default safe assumption

    def _repo_and_pr(self, request: TransitionCheckRequest) -> tuple[str, Optional[int]]:
        repo = request.context_overrides.get("repo", "unknown")
        pr_number = request.context_overrides.get("pr_number")
        try:
            pr = int(pr_number) if pr_number is not None else None
        except Exception:
            pr = None
        return repo, pr

    def _build_decision(
        self,
        request: TransitionCheckRequest,
        *,
        release_status: DecisionType,
        message: str,
        evaluation_key: str,
        unlock_conditions: Optional[List[str]] = None,
        matched_policies: Optional[List[str]] = None,
        reason_code: Optional[str] = None,
        inputs_present: Optional[Dict[str, bool]] = None,
        policy_hash: Optional[str] = None,
    ) -> Decision:
        repo, pr_number = self._repo_and_pr(request)
        return Decision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            release_status=release_status,
            context_id=f"jira-{request.issue_key}",
            message=message,
            requirements=None,
            unlock_conditions=unlock_conditions or [],
            matched_policies=matched_policies or [],
            policy_bundle_hash=policy_hash or self._current_policy_hash(),
            evaluation_key=evaluation_key,
            actor_id=request.actor_account_id,
            reason_code=reason_code,
            inputs_present=inputs_present or {},
            enforcement_targets=EnforcementTargets(
                repository=repo,
                pr_number=pr_number,
                ref=request.context_overrides.get("ref", "HEAD"),
                external={"jira": [request.issue_key]},
            ),
        )

    def _is_missing_risk_metadata(self, risk_meta: Dict[str, Any]) -> bool:
        if not risk_meta:
            return True
        level = risk_meta.get("releasegate_risk") or risk_meta.get("risk_level")
        return not bool(level)

    def _reason_code_for_status(self, status: str) -> str:
        if status == "BLOCKED":
            return "POLICY_BLOCKED"
        if status == "CONDITIONAL":
            return "POLICY_CONDITIONAL"
        return "POLICY_ALLOWED"

    def _evaluate_policy_results(self, relevant_results: List[Any]) -> tuple[DecisionType, List[str], List[str]]:
        """
        Pure decision reduction: policy results -> (status, blocking_policy_ids, requirements)
        """
        status = DecisionType.ALLOWED
        blocking_policies: List[str] = []
        requirements: List[str] = []

        for res in relevant_results:
            if res.status == "BLOCK":
                status = DecisionType.BLOCKED
                blocking_policies.append(res.policy_id)
                requirements.extend(res.violations)
            elif res.status == "WARN" and status != DecisionType.BLOCKED:
                status = DecisionType.CONDITIONAL
                requirements.extend(res.violations)

        return status, blocking_policies, requirements
