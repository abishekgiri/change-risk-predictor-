import hashlib
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Callable, TypeVar
import requests
from releasegate.attestation.canonicalize import canonicalize_json_bytes
from releasegate.integrations.github_risk import PRRiskInput, build_issue_risk_property, classify_pr_risk
from releasegate.integrations.jira.types import TransitionCheckRequest, TransitionCheckResponse
from releasegate.integrations.jira.client import JiraClient, JiraDependencyTimeout
from releasegate.integrations.jira.config import (
    JiraRoleMap,
    JiraTransitionMap,
    load_role_map,
    load_transition_map,
    resolve_gate_policy_ids,
)
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets, DecisionType, PolicyBinding
from releasegate.policy.loader import PolicyLoader
from releasegate.policy.policy_types import Policy
from releasegate.observability.internal_metrics import incr
from releasegate.security.audit import log_security_event
from releasegate.storage.base import resolve_tenant_id
from releasegate.utils.ttl_cache import TTLCache, file_fingerprint, stable_tuple, yaml_tree_fingerprint

logger = logging.getLogger(__name__)
T = TypeVar("T")


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except Exception:
        return default


_TRANSITION_MAP_CACHE = TTLCache(
    max_entries=max(1, _env_int("RELEASEGATE_TRANSITION_MAP_CACHE_MAX_ENTRIES", 256)),
    default_ttl_seconds=max(1.0, _env_float("RELEASEGATE_TRANSITION_MAP_CACHE_TTL_SECONDS", 300.0)),
)
_ROLE_MAP_CACHE = TTLCache(
    max_entries=max(1, _env_int("RELEASEGATE_ROLE_MAP_CACHE_MAX_ENTRIES", 256)),
    default_ttl_seconds=max(1.0, _env_float("RELEASEGATE_ROLE_MAP_CACHE_TTL_SECONDS", 300.0)),
)
_ROLE_RESOLUTION_CACHE = TTLCache(
    max_entries=max(1, _env_int("RELEASEGATE_ROLE_RESOLUTION_CACHE_MAX_ENTRIES", 2048)),
    default_ttl_seconds=max(1.0, _env_float("RELEASEGATE_ROLE_RESOLUTION_CACHE_TTL_SECONDS", 180.0)),
)
_POLICY_REGISTRY_CACHE = TTLCache(
    max_entries=max(1, _env_int("RELEASEGATE_POLICY_REGISTRY_CACHE_MAX_ENTRIES", 256)),
    default_ttl_seconds=max(1.0, _env_float("RELEASEGATE_POLICY_REGISTRY_CACHE_TTL_SECONDS", 300.0)),
)

class WorkflowGate:
    def __init__(self):
        self.client = JiraClient()
        self.policy_map_path = "releasegate/integrations/jira/jira_transition_map.yaml"
        self.role_map_path = "releasegate/integrations/jira/jira_role_map.yaml"
        self.strict_mode = os.getenv("RELEASEGATE_STRICT_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
        self.dependency_timeout_seconds = float(os.getenv("RELEASEGATE_JIRA_DEP_TIMEOUT_SECONDS", "5"))
        self.ci_score_timeout_seconds = float(os.getenv("RELEASEGATE_CI_SCORE_TIMEOUT_SECONDS", "5"))
        self.storage_timeout_seconds = float(os.getenv("RELEASEGATE_STORAGE_TIMEOUT_SECONDS", "3"))
        self.policy_timeout_seconds = float(os.getenv("RELEASEGATE_POLICY_REGISTRY_TIMEOUT_SECONDS", "3"))
        self.transition_map_cache_ttl_seconds = _env_float("RELEASEGATE_TRANSITION_MAP_CACHE_TTL_SECONDS", 300.0)
        self.role_map_cache_ttl_seconds = _env_float("RELEASEGATE_ROLE_MAP_CACHE_TTL_SECONDS", 300.0)
        self.role_resolution_cache_ttl_seconds = _env_float("RELEASEGATE_ROLE_RESOLUTION_CACHE_TTL_SECONDS", 180.0)
        self.policy_registry_cache_ttl_seconds = _env_float("RELEASEGATE_POLICY_REGISTRY_CACHE_TTL_SECONDS", 300.0)
        self._active_tenant_id: Optional[str] = None
        self._policy_hash_cache: Optional[str] = None
        self._resolved_mode_hint: Optional[str] = None
        self._resolved_gate_hint: Optional[str] = None
        self._unresolved_gate_hint: Optional[str] = None

    def check_transition(self, request: TransitionCheckRequest) -> TransitionCheckResponse:
        """
        Evaluate if a Jira transition is allowed.
        Enforces idempotency, audit-on-error, and policy gates.
        """
        tenant_id = self._tenant_id(request)
        self._active_tenant_id = tenant_id
        self._policy_hash_cache = None
        evaluation_key = self._compute_key(request, tenant_id=tenant_id)
        repo, pr_number = self._repo_and_pr(request)
        is_prod = request.environment.upper() == "PRODUCTION"
        strict_mode = self.strict_mode or is_prod
        self._resolved_mode_hint = None
        self._resolved_gate_hint = None
        self._unresolved_gate_hint = None
        try:
            policies = self._resolve_policies(request)
        except TimeoutError as exc:
            return self._dependency_timeout_response(
                request,
                dependency="policy_registry",
                evaluation_key=evaluation_key,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                strict_mode=strict_mode or is_prod,
                detail=str(exc),
            )
        strict_mode = self._effective_strict_mode(self._resolved_mode_hint, default=strict_mode) or is_prod
        request_id = (
            request.context_overrides.get("delivery_id")
            or request.context_overrides.get("idempotency_key")
            or evaluation_key[:16]
        )

        self._log_event(
            "info",
            event="jira.transition.evaluate.start",
            tenant_id=tenant_id,
            decision_id="pending",
            request_id=request_id,
            issue_key=request.issue_key,
            transition_id=request.transition_id,
            repo=repo,
            pr_number=pr_number,
            mode="strict" if strict_mode else "permissive",
            result="PENDING",
            reason_code="PENDING",
            policy_bundle_hash=self._current_policy_hash(),
            evaluation_key=evaluation_key,
            gate=self._resolved_gate_hint,
        )
        incr("transitions_evaluated", tenant_id=tenant_id)

        # In strict mode, when repo/PR context is provided, verify dependency truth before
        # trusting persisted Jira issue properties. This prevents stale metadata replay.
        strict_dependency_failure = self._strict_dependency_failure(repo=repo, pr_number=pr_number)
        if strict_mode and strict_dependency_failure is not None:
            reason_code, message, unlock_conditions = strict_dependency_failure
            blocked = self._build_decision(
                request,
                release_status=DecisionType.BLOCKED,
                message=message,
                evaluation_key=f"{evaluation_key}:strict-dependency",
                unlock_conditions=unlock_conditions,
                reason_code=reason_code,
                inputs_present={"releasegate_risk": False},
                policy_hash=self._current_policy_hash(),
                input_snapshot={
                    "request": request.model_dump(mode="json"),
                    "repo": repo,
                    "pr_number": pr_number,
                },
            )
            final_blocked = self._record_with_timeout(
                blocked,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                strict_mode=strict_mode,
                dependency_context="storage",
            )
            self._log_decision(
                event="jira.transition.strict_dependency_failed",
                request=request,
                decision=final_blocked,
                repo=repo,
                pr_number=pr_number,
                mode=strict_mode,
                gate=self._resolved_gate_hint,
                error_code=reason_code,
                dependency="github",
            )
            self._track_status_metrics(final_blocked.release_status, tenant_id=tenant_id)
            return TransitionCheckResponse(
                allow=False,
                reason=final_blocked.message,
                decision_id=final_blocked.decision_id,
                status=final_blocked.release_status.value,
                reason_code=final_blocked.reason_code,
                unlock_conditions=final_blocked.unlock_conditions,
                policy_hash=final_blocked.policy_bundle_hash,
                tenant_id=tenant_id,
            )

        # Override path with explicit ledger recording
        if request.context_overrides.get("override") is True:
            override_reason = str(request.context_overrides.get("override_reason", "") or "").strip()
            normalized_override_reason = override_reason or "override"
            override_expires_at = self._parse_iso_datetime(request.context_overrides.get("override_expires_at"))
            justification_required = bool(request.context_overrides.get("override_justification_required", False))
            actor_principals = self._principal_set(
                request.actor_account_id,
                request.actor_email,
            )
            pr_author_principals = self._principal_set(
                request.context_overrides.get("pr_author_account_id"),
                request.context_overrides.get("pr_author_email"),
                request.context_overrides.get("pr_author"),
            )
            override_requestor_principals = self._principal_set(
                request.context_overrides.get("override_requested_by_account_id"),
                request.context_overrides.get("override_requested_by_email"),
                request.context_overrides.get("override_requested_by"),
                request.context_overrides.get("override_created_by_account_id"),
                request.context_overrides.get("override_created_by_email"),
            )

            if actor_principals and pr_author_principals and actor_principals.intersection(pr_author_principals):
                blocked = self._build_decision(
                    request,
                    release_status=DecisionType.BLOCKED,
                    message="BLOCKED: separation-of-duties violation (PR author cannot approve override)",
                    evaluation_key=f"{evaluation_key}:override-sod-pr-author",
                    unlock_conditions=["Use an approver different from the PR author."],
                    reason_code="SOD_PR_AUTHOR_CANNOT_OVERRIDE",
                    inputs_present={"override_requested": True},
                    policy_hash=self._current_policy_hash(),
                    input_snapshot={"request": request.model_dump(mode="json")},
                )
                final_blocked = self._record_with_timeout(
                    blocked,
                    repo=repo,
                    pr_number=pr_number,
                    tenant_id=tenant_id,
                    strict_mode=strict_mode,
                    dependency_context="storage",
                )
                self._track_status_metrics(final_blocked.release_status, tenant_id=tenant_id)
                self._log_decision(
                    event="jira.transition.override.sod_pr_author",
                    request=request,
                    decision=final_blocked,
                    repo=repo,
                    pr_number=pr_number,
                    mode=strict_mode,
                    gate=self._resolved_gate_hint,
                )
                return TransitionCheckResponse(
                    allow=final_blocked.release_status != DecisionType.BLOCKED,
                    reason=final_blocked.message,
                    decision_id=final_blocked.decision_id,
                    status=final_blocked.release_status.value,
                    reason_code=final_blocked.reason_code,
                    unlock_conditions=final_blocked.unlock_conditions,
                    policy_hash=final_blocked.policy_bundle_hash,
                    tenant_id=tenant_id,
                )

            if actor_principals and override_requestor_principals and actor_principals.intersection(override_requestor_principals):
                blocked = self._build_decision(
                    request,
                    release_status=DecisionType.BLOCKED,
                    message="BLOCKED: separation-of-duties violation (override requestor cannot self-approve)",
                    evaluation_key=f"{evaluation_key}:override-sod-requestor",
                    unlock_conditions=["Use an approver different from the override requestor."],
                    reason_code="SOD_REQUESTOR_CANNOT_SELF_APPROVE",
                    inputs_present={"override_requested": True},
                    policy_hash=self._current_policy_hash(),
                    input_snapshot={"request": request.model_dump(mode="json")},
                )
                final_blocked = self._record_with_timeout(
                    blocked,
                    repo=repo,
                    pr_number=pr_number,
                    tenant_id=tenant_id,
                    strict_mode=strict_mode,
                    dependency_context="storage",
                )
                self._track_status_metrics(final_blocked.release_status, tenant_id=tenant_id)
                self._log_decision(
                    event="jira.transition.override.sod_requestor",
                    request=request,
                    decision=final_blocked,
                    repo=repo,
                    pr_number=pr_number,
                    mode=strict_mode,
                    gate=self._resolved_gate_hint,
                )
                return TransitionCheckResponse(
                    allow=final_blocked.release_status != DecisionType.BLOCKED,
                    reason=final_blocked.message,
                    decision_id=final_blocked.decision_id,
                    status=final_blocked.release_status.value,
                    reason_code=final_blocked.reason_code,
                    unlock_conditions=final_blocked.unlock_conditions,
                    policy_hash=final_blocked.policy_bundle_hash,
                    tenant_id=tenant_id,
                )

            if justification_required and not override_reason:
                blocked = self._build_decision(
                    request,
                    release_status=DecisionType.BLOCKED,
                    message="BLOCKED: override justification is required",
                    evaluation_key=f"{evaluation_key}:override-missing-justification",
                    unlock_conditions=["Provide override_reason to apply an override."],
                    reason_code="OVERRIDE_JUSTIFICATION_REQUIRED",
                    inputs_present={"override_requested": True},
                    policy_hash=self._current_policy_hash(),
                    input_snapshot={"request": request.model_dump(mode="json")},
                )
                final_blocked = self._record_with_timeout(
                    blocked,
                    repo=repo,
                    pr_number=pr_number,
                    tenant_id=tenant_id,
                    strict_mode=strict_mode,
                    dependency_context="storage",
                )
                self._track_status_metrics(final_blocked.release_status, tenant_id=tenant_id)
                self._log_decision(
                    event="jira.transition.override.justification_required",
                    request=request,
                    decision=final_blocked,
                    repo=repo,
                    pr_number=pr_number,
                    mode=strict_mode,
                    gate=self._resolved_gate_hint,
                )
                return TransitionCheckResponse(
                    allow=final_blocked.release_status != DecisionType.BLOCKED,
                    reason=final_blocked.message,
                    decision_id=final_blocked.decision_id,
                    status=final_blocked.release_status.value,
                    reason_code=final_blocked.reason_code,
                    unlock_conditions=final_blocked.unlock_conditions,
                    policy_hash=final_blocked.policy_bundle_hash,
                    tenant_id=tenant_id,
                )

            if override_expires_at and datetime.now(timezone.utc) > override_expires_at:
                blocked = self._build_decision(
                    request,
                    release_status=DecisionType.BLOCKED,
                    message=f"BLOCKED: override expired at {override_expires_at.isoformat()}",
                    evaluation_key=f"{evaluation_key}:override-expired",
                    unlock_conditions=["Request a new override with a future override_expires_at."],
                    reason_code="OVERRIDE_EXPIRED",
                    inputs_present={"override_requested": True},
                    policy_hash=self._current_policy_hash(),
                    input_snapshot={"request": request.model_dump(mode="json")},
                )
                final_blocked = self._record_with_timeout(
                    blocked,
                    repo=repo,
                    pr_number=pr_number,
                    tenant_id=tenant_id,
                    strict_mode=strict_mode,
                    dependency_context="storage",
                )
                self._track_status_metrics(final_blocked.release_status, tenant_id=tenant_id)
                self._log_decision(
                    event="jira.transition.override.expired",
                    request=request,
                    decision=final_blocked,
                    repo=repo,
                    pr_number=pr_number,
                    mode=strict_mode,
                    gate=self._resolved_gate_hint,
                )
                return TransitionCheckResponse(
                    allow=final_blocked.release_status != DecisionType.BLOCKED,
                    reason=final_blocked.message,
                    decision_id=final_blocked.decision_id,
                    status=final_blocked.release_status.value,
                    reason_code=final_blocked.reason_code,
                    unlock_conditions=final_blocked.unlock_conditions,
                    policy_hash=final_blocked.policy_bundle_hash,
                    tenant_id=tenant_id,
                )

            decision = self._build_decision(
                request,
                release_status=DecisionType.ALLOWED,
                message=f"Override applied: {normalized_override_reason}",
                evaluation_key=f"{evaluation_key}:override",
                unlock_conditions=[normalized_override_reason],
                reason_code="OVERRIDE_APPLIED",
                inputs_present={
                    "releasegate_risk": True,
                    "override_requested": True,
                    "override_expiry_present": bool(override_expires_at),
                },
                policy_hash=self._current_policy_hash(),
                input_snapshot={"request": request.model_dump(mode="json")},
            )
            final_decision = self._record_with_timeout(
                decision,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                strict_mode=strict_mode,
                dependency_context="storage",
            )
            try:
                from releasegate.audit.overrides import record_override
                override_idempotency_key = hashlib.sha256(
                    f"{evaluation_key}:override-ledger:{request.issue_key}:{request.actor_account_id}".encode("utf-8")
                ).hexdigest()
                record_override(
                    repo=repo,
                    pr_number=pr_number,
                    issue_key=request.issue_key,
                    decision_id=final_decision.decision_id,
                    actor=request.actor_email or request.actor_account_id,
                    reason=normalized_override_reason,
                    idempotency_key=override_idempotency_key,
                    tenant_id=tenant_id,
                )
                log_security_event(
                    tenant_id=tenant_id,
                    principal_id=request.actor_account_id or "jira-workflow",
                    auth_method="signature",
                    action="override_create",
                    target_type="issue",
                    target_id=request.issue_key,
                    metadata={
                        "decision_id": final_decision.decision_id,
                        "repo": repo,
                        "pr_number": pr_number,
                    },
                )
            except Exception as e:
                self._log_event(
                    "warning",
                    event="jira.transition.override.ledger_write_failed",
                    tenant_id=tenant_id,
                    decision_id=final_decision.decision_id,
                    request_id=request.context_overrides.get("delivery_id")
                    or request.context_overrides.get("idempotency_key")
                    or evaluation_key[:16],
                    issue_key=request.issue_key,
                    transition_id=request.transition_id,
                    repo=repo,
                    pr_number=pr_number,
                    mode="strict" if strict_mode else "permissive",
                    result=final_decision.release_status.value,
                    reason_code=final_decision.reason_code,
                    policy_bundle_hash=final_decision.policy_bundle_hash,
                    error_code="OVERRIDE_LEDGER_WRITE_FAILED",
                    error=str(e),
                )
            self._log_decision(
                event="jira.transition.override.applied",
                request=request,
                decision=final_decision,
                repo=repo,
                pr_number=pr_number,
                mode=strict_mode,
                gate=self._resolved_gate_hint,
            )
            incr("overrides_used", tenant_id=tenant_id)
            self._track_status_metrics(final_decision.release_status, tenant_id=tenant_id)
            return TransitionCheckResponse(
                allow=final_decision.release_status != DecisionType.BLOCKED,
                reason=final_decision.message,
                decision_id=final_decision.decision_id,
                status=final_decision.release_status.value,
                reason_code=final_decision.reason_code,
                unlock_conditions=final_decision.unlock_conditions,
                policy_hash=final_decision.policy_bundle_hash,
                tenant_id=tenant_id,
            )

        # Fail-open explicitly with an audited SKIPPED decision when Jira risk metadata is missing.
        try:
            risk_meta = self._call_with_timeout(
                "jira_api",
                self.client.get_issue_property,
                self.dependency_timeout_seconds,
                request.issue_key,
                "releasegate_risk",
            )
        except JiraDependencyTimeout as exc:
            return self._dependency_timeout_response(
                request,
                dependency="jira_api",
                evaluation_key=evaluation_key,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                strict_mode=strict_mode,
                detail=str(exc),
            )
        except TimeoutError as exc:
            return self._dependency_timeout_response(
                request,
                dependency="jira_api",
                evaluation_key=evaluation_key,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                strict_mode=strict_mode,
                detail=str(exc),
            )
        except Exception as e:
            return self._error_response(
                request,
                evaluation_key=evaluation_key,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                message=f"System Error: failed to fetch issue property `releasegate_risk` ({e})",
                reason_code="RISK_METADATA_FETCH_ERROR",
                strict_mode=strict_mode,
                error_code="RISK_METADATA_FETCH_ERROR",
            )

        if self._is_missing_risk_metadata(risk_meta):
            ci_risk_meta = self._fetch_risk_metadata_from_ci(repo=repo, pr_number=pr_number)
            if ci_risk_meta:
                risk_meta = ci_risk_meta
                try:
                    self._call_with_timeout(
                        "jira_api",
                        self.client.set_issue_property,
                        self.dependency_timeout_seconds,
                        request.issue_key,
                        "releasegate_risk",
                        ci_risk_meta,
                    )
                except Exception:
                    # Best-effort persistence. Keep evaluation moving even if Jira write fails.
                    pass

        if self._is_missing_risk_metadata(risk_meta):
            missing_status = DecisionType.BLOCKED if strict_mode else DecisionType.SKIPPED
            missing_reason = (
                "BLOCKED: missing issue property `releasegate_risk` (strict mode)"
                if strict_mode
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
                reason_code="MISSING_RISK_METADATA_STRICT" if strict_mode else "MISSING_RISK_METADATA",
                inputs_present={"releasegate_risk": False},
                policy_hash=self._current_policy_hash(),
                input_snapshot={
                    "request": request.model_dump(mode="json"),
                    "risk_meta": risk_meta,
                },
            )
            final_skipped = self._record_with_timeout(
                skipped,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                strict_mode=strict_mode,
                dependency_context="storage",
            )
            self._log_decision(
                event="jira.transition.missing_risk",
                request=request,
                decision=final_skipped,
                repo=repo,
                pr_number=pr_number,
                mode=strict_mode,
                gate=self._resolved_gate_hint,
            )
            self._track_status_metrics(final_skipped.release_status, tenant_id=tenant_id)
            return TransitionCheckResponse(
                allow=final_skipped.release_status != DecisionType.BLOCKED,
                reason=final_skipped.message,
                decision_id=final_skipped.decision_id,
                status=final_skipped.release_status.value,
                reason_code=final_skipped.reason_code,
                requirements=["Missing `releasegate_risk` metadata"],
                unlock_conditions=final_skipped.unlock_conditions,
                policy_hash=final_skipped.policy_bundle_hash,
                tenant_id=tenant_id,
            )
        
        try:
            # 1. Idempotency Check
            # In a real high-throughput system you might check DB reader here.
            # For now, we rely on the DB unique constraint in the Recorder to catch duplicates at write time,
            # or we could peek. Let's proceed to evaluate; Recorder handles the "already exists" case safely now.

            role_map = self._load_role_map(tenant_id=tenant_id)
            if strict_mode and role_map is None:
                blocked = self._build_decision(
                    request,
                    release_status=DecisionType.BLOCKED,
                    message="BLOCKED: Jira role mapping unavailable (strict mode)",
                    evaluation_key=f"{evaluation_key}:missing-role-map",
                    unlock_conditions=["Restore valid jira_role_map.yaml and retry transition."],
                    reason_code="ROLE_MAPPING_MISSING",
                    inputs_present={"releasegate_risk": True},
                    policy_hash=self._current_policy_hash(),
                    input_snapshot={
                        "request": request.model_dump(mode="json"),
                        "risk_meta": risk_meta,
                    },
                )
                final_blocked = self._record_with_timeout(
                    blocked,
                    repo=repo,
                    pr_number=pr_number,
                    tenant_id=tenant_id,
                    strict_mode=strict_mode,
                    dependency_context="storage",
                )
                self._log_decision(
                    event="jira.transition.role_map_missing",
                    request=request,
                    decision=final_blocked,
                    repo=repo,
                    pr_number=pr_number,
                    mode=strict_mode,
                    gate=self._resolved_gate_hint,
                )
                self._track_status_metrics(final_blocked.release_status, tenant_id=tenant_id)
                return TransitionCheckResponse(
                    allow=False,
                    reason=final_blocked.message,
                    decision_id=final_blocked.decision_id,
                    status=final_blocked.release_status.value,
                    reason_code=final_blocked.reason_code,
                    unlock_conditions=final_blocked.unlock_conditions,
                    policy_hash=final_blocked.policy_bundle_hash,
                    tenant_id=tenant_id,
                )
            
            # 2. Context Construction
            context = self._build_context(request)
            
            # 3. Policy Resolution
            if self._unresolved_gate_hint:
                invalid_status = DecisionType.BLOCKED if strict_mode else DecisionType.SKIPPED
                invalid_reason = (
                    f"BLOCKED: invalid gate reference: {self._unresolved_gate_hint} (strict mode)"
                    if strict_mode
                    else f"SKIPPED: invalid gate reference: {self._unresolved_gate_hint}"
                )
                invalid = self._build_decision(
                    request,
                    release_status=invalid_status,
                    message=invalid_reason,
                    evaluation_key=f"{evaluation_key}:invalid-gate",
                    unlock_conditions=["Fix Jira transition gate mapping in jira_transition_map.yaml."],
                    reason_code="INVALID_POLICY_REFERENCE_STRICT" if strict_mode else "INVALID_POLICY_REFERENCE",
                    inputs_present={"releasegate_risk": True},
                    policy_hash=self._current_policy_hash(),
                    input_snapshot={
                        "request": request.model_dump(mode="json"),
                        "risk_meta": risk_meta,
                        "gate": self._unresolved_gate_hint,
                    },
                )
                final_invalid = self._record_with_timeout(
                    invalid,
                    repo=repo,
                    pr_number=pr_number,
                    tenant_id=tenant_id,
                    strict_mode=strict_mode,
                    dependency_context="storage",
                )
                self._log_decision(
                    event="jira.transition.invalid_gate",
                    request=request,
                    decision=final_invalid,
                    repo=repo,
                    pr_number=pr_number,
                    mode=strict_mode,
                    gate=self._resolved_gate_hint,
                )
                self._track_status_metrics(final_invalid.release_status, tenant_id=tenant_id)
                return TransitionCheckResponse(
                    allow=final_invalid.release_status != DecisionType.BLOCKED,
                    reason=final_invalid.message,
                    decision_id=final_invalid.decision_id,
                    status=final_invalid.release_status.value,
                    reason_code=final_invalid.reason_code,
                    unlock_conditions=final_invalid.unlock_conditions,
                    policy_hash=final_invalid.policy_bundle_hash,
                    tenant_id=tenant_id,
                )

            if not policies:
                # No policies mapped -> strict mode blocks, otherwise explicit audited skip.
                no_policy_status = DecisionType.BLOCKED if strict_mode else DecisionType.SKIPPED
                no_policy_reason = (
                    "BLOCKED: no policies configured for this transition (strict mode)"
                    if strict_mode
                    else "SKIPPED: no policies configured for this transition"
                )
                skipped = self._build_decision(
                    request,
                    release_status=no_policy_status,
                    message=no_policy_reason,
                    evaluation_key=f"{evaluation_key}:no-policy",
                    unlock_conditions=["Map this transition to one or more policy IDs."],
                    reason_code="NO_POLICIES_MAPPED_STRICT" if strict_mode else "NO_POLICIES_MAPPED",
                    inputs_present={"releasegate_risk": True},
                    policy_hash=self._current_policy_hash(),
                    input_snapshot={
                        "request": request.model_dump(mode="json"),
                        "policies_requested": [],
                        "risk_meta": risk_meta,
                    },
                )
                final_skipped = self._record_with_timeout(
                    skipped,
                    repo=repo,
                    pr_number=pr_number,
                    tenant_id=tenant_id,
                    strict_mode=strict_mode,
                    dependency_context="storage",
                )
                self._log_decision(
                    event="jira.transition.no_policy",
                    request=request,
                    decision=final_skipped,
                    repo=repo,
                    pr_number=pr_number,
                    mode=strict_mode,
                    gate=self._resolved_gate_hint,
                )
                self._track_status_metrics(final_skipped.release_status, tenant_id=tenant_id)
                return TransitionCheckResponse(
                    allow=final_skipped.release_status != DecisionType.BLOCKED,
                    reason=final_skipped.message,
                    decision_id=final_skipped.decision_id,
                    status=final_skipped.release_status.value,
                    reason_code=final_skipped.reason_code,
                    unlock_conditions=final_skipped.unlock_conditions,
                    policy_hash=final_skipped.policy_bundle_hash,
                    tenant_id=tenant_id,
                )

            # 4. Evaluation
            # We must convert the EvaluationContext to a signal dict that ComplianceEngine expects
            # Phase 10 MVP: we flatten context into a dict
            risk_level = risk_meta.get("releasegate_risk") or risk_meta.get("risk_level") or risk_meta.get("severity_level")
            risk_score = risk_meta.get("risk_score") or risk_meta.get("severity")
            risk_metrics = risk_meta.get("metrics") if isinstance(risk_meta.get("metrics"), dict) else {}
            signal_map = {
                "repo": context.change.repository,
                "pr_number": int(context.change.change_id) if context.change.change_id.isdigit() else 0,
                "diff": {}, 
                "labels": [],
                "user": {"login": context.actor.login, "role": context.actor.role},
                "environment": context.environment,
                "transition": {
                    "source_status": request.source_status,
                    "target_status": request.target_status,
                    "name": request.transition_name or ""
                },
                "risk": {
                    "level": risk_level,
                    "score": risk_score,
                    "changed_files_count": risk_metrics.get("changed_files_count"),
                    "additions": risk_metrics.get("additions"),
                    "deletions": risk_metrics.get("deletions"),
                    "total_churn": risk_metrics.get("total_churn"),
                    "source": risk_meta.get("source"),
                    "computed_at": risk_meta.get("computed_at"),
                },
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
            compiled_policy_map = self._compiled_policy_map()
            unresolved_policy_ids = sorted(set(policies) - set(compiled_policy_map.keys()))
            policy_bindings = self._build_policy_bindings(policies, compiled_policy_map, tenant_id=tenant_id)
            bindings_hash = self._policy_bindings_hash(policy_bindings)
            
            # Run ALL policies (Engine doesn't support filtering input yet)
            run_result = engine.evaluate(signal_map)
            
            # Filter results to ONLY the policies required by this Jira transition
            relevant_results = [r for r in run_result.results if r.policy_id in policies]
            policy_hash = bindings_hash or self._current_policy_hash()

            if unresolved_policy_ids:
                invalid_status = DecisionType.BLOCKED if strict_mode else DecisionType.SKIPPED
                invalid_message = (
                    f"BLOCKED: invalid policy references: {', '.join(unresolved_policy_ids)} (strict mode)"
                    if strict_mode
                    else f"SKIPPED: invalid policy references: {', '.join(unresolved_policy_ids)}"
                )
                invalid = self._build_decision(
                    request,
                    release_status=invalid_status,
                    message=invalid_message,
                    evaluation_key=f"{evaluation_key}:invalid-policy",
                    unlock_conditions=["Fix Jira transition policy mapping to compiled policy IDs."],
                    reason_code="INVALID_POLICY_REFERENCE_STRICT" if strict_mode else "INVALID_POLICY_REFERENCE",
                    inputs_present={"releasegate_risk": True},
                    policy_hash=policy_hash,
                    policy_bindings=policy_bindings,
                    input_snapshot={
                        "request": request.model_dump(mode="json"),
                        "signal_map": signal_map,
                        "policies_requested": policies,
                        "strict_mode": strict_mode,
                        "risk_meta": risk_meta,
                    },
                )
                final_invalid = self._record_with_timeout(
                    invalid,
                    repo=repo,
                    pr_number=pr_number,
                    tenant_id=tenant_id,
                    strict_mode=strict_mode,
                    dependency_context="storage",
                )
                self._log_decision(
                    event="jira.transition.invalid_policy_reference",
                    request=request,
                    decision=final_invalid,
                    repo=repo,
                    pr_number=pr_number,
                    mode=strict_mode,
                    gate=self._resolved_gate_hint,
                    policy_bundle_hash=final_invalid.policy_bundle_hash,
                )
                self._track_status_metrics(final_invalid.release_status, tenant_id=tenant_id)
                return TransitionCheckResponse(
                    allow=final_invalid.release_status != DecisionType.BLOCKED,
                    reason=final_invalid.message,
                    decision_id=final_invalid.decision_id,
                    status=final_invalid.release_status.value,
                    reason_code=final_invalid.reason_code,
                    unlock_conditions=final_invalid.unlock_conditions,
                    policy_hash=final_invalid.policy_bundle_hash,
                    tenant_id=tenant_id,
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
                policy_bindings=policy_bindings,
                input_snapshot={
                    "request": request.model_dump(mode="json"),
                    "signal_map": signal_map,
                    "policies_requested": policies,
                    "strict_mode": strict_mode,
                    "risk_meta": risk_meta,
                },
            )
            
            # 6. Audit Recording
            # This handles duplicate inserts (idempotency) by returning existing decision if present
            final_decision = self._record_with_timeout(
                decision,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                strict_mode=strict_mode,
                dependency_context="storage",
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
            self._log_decision(
                event="jira.transition.evaluated",
                request=request,
                decision=final_decision,
                repo=repo,
                pr_number=pr_number,
                mode=strict_mode,
                gate=self._resolved_gate_hint,
                result=status.value,
            )
            self._track_status_metrics(status, tenant_id=tenant_id)
            
            return TransitionCheckResponse(
                allow=allow,
                reason=reason,
                decision_id=final_decision.decision_id,
                status=status.value,
                reason_code=final_decision.reason_code,
                requirements=resp_requirements,
                unlock_conditions=final_decision.unlock_conditions,
                policy_hash=final_decision.policy_bundle_hash,
                tenant_id=tenant_id,
            )

        except TimeoutError as e:
            return self._dependency_timeout_response(
                request,
                dependency="policy_registry",
                evaluation_key=evaluation_key,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                strict_mode=strict_mode,
                detail=str(e),
            )
        except Exception as e:
            self._log_event(
                "error",
                event="jira.transition.unhandled_exception",
                tenant_id=tenant_id,
                decision_id="pending",
                request_id=request_id,
                issue_key=request.issue_key,
                transition_id=request.transition_id,
                repo=repo,
                pr_number=pr_number,
                mode="strict" if strict_mode else "permissive",
                result="ERROR",
                reason_code="SYSTEM_ERROR",
                error_code="SYSTEM_ERROR",
                error=str(e),
            )
            return self._error_response(
                request,
                evaluation_key=evaluation_key,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
                message=f"System Error: {str(e)}",
                reason_code="SYSTEM_ERROR",
                strict_mode=strict_mode,
                error_code="SYSTEM_ERROR",
            )

    def _compute_key(self, req: TransitionCheckRequest, tenant_id: Optional[str] = None) -> str:
        """Deterministic SHA256 key over canonical transition inputs."""
        effective_tenant = resolve_tenant_id(tenant_id or req.tenant_id or req.context_overrides.get("tenant_id"))
        repo, pr_number = self._repo_and_pr(req)
        seed = {
            "version": 1,
            "tenant_id": effective_tenant,
            "issue_key": req.issue_key,
            "transition_id": req.transition_id,
            "source_status": req.source_status,
            "target_status": req.target_status,
            "environment": req.environment,
            "project_key": req.project_key,
            "issue_type": req.issue_type,
            "repo": repo,
            "pr_number": pr_number,
            "actor_account_id": req.actor_account_id,
        }
        return hashlib.sha256(canonicalize_json_bytes(seed)).hexdigest()

    def _tenant_id(self, req: TransitionCheckRequest) -> str:
        return resolve_tenant_id(req.tenant_id or req.context_overrides.get("tenant_id"))

    def _cache_tenant(self, tenant_id: Optional[str] = None) -> str:
        return resolve_tenant_id(tenant_id or self._active_tenant_id, allow_none=True) or "system"

    def _role_map_hash(self, role_map: JiraRoleMap) -> str:
        payload = json.dumps(role_map.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _build_context(self, req: TransitionCheckRequest):
        """Construct the EvaluationContext from Jira request + Jira API data."""
        from releasegate.context.types import EvaluationContext, Actor, Change, Timing
        
        # 1. Resolve Role
        role = self._resolve_role(req, tenant_id=self._tenant_id(req))
        
        # 2. Extract PR (Change Context)
        repo = req.context_overrides.get("repo", "unknown/repo")
        pr_id = "0"
        
        # Try Dev Status if no override
        if "repo" not in req.context_overrides:
            # Fetch from Jira
            # For MVP, we skip the complex dev-status parsing logic and fallback to regex/custom field
            # Real impl would call self.client.get_dev_status(req.issue_id)
            self._log_event(
                "info",
                event="jira.transition.context.repo_not_provided",
                tenant_id=self._tenant_id(req),
                decision_id="pending",
                request_id=req.context_overrides.get("delivery_id")
                or req.context_overrides.get("idempotency_key")
                or self._compute_key(req, tenant_id=req.tenant_id)[:16],
                issue_key=req.issue_key,
                transition_id=req.transition_id,
                repo=repo,
                pr_number=None,
                mode="strict" if self.strict_mode else "permissive",
                result="PENDING",
                reason_code="PENDING",
            )
            
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
        """Resolve policy IDs from Jira transition mapping config."""
        effective_tenant = self._tenant_id(req)
        transition_map = self._load_transition_map(tenant_id=effective_tenant)
        if not transition_map:
            return []

        self._resolved_mode_hint = None
        self._resolved_gate_hint = None
        self._unresolved_gate_hint = None

        global_projects = {p.upper() for p in transition_map.jira.project_keys}
        if global_projects and req.project_key.upper() not in global_projects:
            return []
        global_issue_types = {issue_type.lower() for issue_type in transition_map.jira.issue_types}
        if global_issue_types and req.issue_type.lower() not in global_issue_types:
            return []

        matched_rule = None
        transition_name = (req.transition_name or "").strip().lower()
        for rule in transition_map.transitions:
            if rule.transition_id and rule.transition_id == req.transition_id:
                matched_rule = rule
                break
            if rule.transition_name and transition_name and rule.transition_name.strip().lower() == transition_name:
                matched_rule = rule
                break

        if not matched_rule:
            return []

        scoped_projects = {p.upper() for p in matched_rule.project_keys}
        if scoped_projects and req.project_key.upper() not in scoped_projects:
            return []
        scoped_issue_types = {issue_type.lower() for issue_type in matched_rule.issue_types}
        if scoped_issue_types and req.issue_type.lower() not in scoped_issue_types:
            return []
        scoped_envs = {env.upper() for env in matched_rule.applies_to.environments}
        if scoped_envs and req.environment.upper() not in scoped_envs:
            return []

        self._resolved_mode_hint = matched_rule.mode
        self._resolved_gate_hint = matched_rule.gate

        known_policy_ids = list(self._compiled_policy_map(tenant_id=effective_tenant).keys())
        resolved_policy_ids, gate_error = resolve_gate_policy_ids(
            transition_map=transition_map,
            gate_name=matched_rule.gate,
            known_policy_ids=known_policy_ids,
        )
        if gate_error:
            self._unresolved_gate_hint = matched_rule.gate
            return []

        deduped: List[str] = []
        seen: set[str] = set()
        for policy_id in resolved_policy_ids:
            if policy_id in seen:
                continue
            seen.add(policy_id)
            deduped.append(policy_id)
        return deduped

    def _load_transition_map(self, tenant_id: Optional[str] = None) -> Optional[JiraTransitionMap]:
        effective_tenant = self._cache_tenant(tenant_id)
        cache_key = (
            effective_tenant,
            os.path.abspath(self.policy_map_path),
            file_fingerprint(self.policy_map_path),
        )
        hit, cached = _TRANSITION_MAP_CACHE.get(cache_key)
        if hit:
            incr("cache_transition_map_hit", tenant_id=effective_tenant)
            return cached
        incr("cache_transition_map_miss", tenant_id=effective_tenant)

        try:
            loaded = self._call_with_timeout(
                "policy_registry",
                load_transition_map,
                self.policy_timeout_seconds,
                self.policy_map_path,
            )
        except TimeoutError:
            raise
        except FileNotFoundError:
            self._log_event(
                "warning",
                event="jira.transition.config.transition_map_missing",
                tenant_id=effective_tenant,
                decision_id="pending",
                request_id="n/a",
                issue_key="n/a",
                transition_id="n/a",
                repo="n/a",
                pr_number=None,
                mode="strict" if self.strict_mode else "permissive",
                result="ERROR",
                reason_code="CONFIG_MISSING",
                error_code="TRANSITION_MAP_NOT_FOUND",
                config_path=self.policy_map_path,
            )
            return None
        except Exception as exc:
            self._log_event(
                "warning",
                event="jira.transition.config.transition_map_invalid",
                tenant_id=effective_tenant,
                decision_id="pending",
                request_id="n/a",
                issue_key="n/a",
                transition_id="n/a",
                repo="n/a",
                pr_number=None,
                mode="strict" if self.strict_mode else "permissive",
                result="ERROR",
                reason_code="CONFIG_INVALID",
                error_code="TRANSITION_MAP_LOAD_FAILED",
                config_path=self.policy_map_path,
                error=str(exc),
            )
            return None
        _TRANSITION_MAP_CACHE.set(
            cache_key,
            loaded,
            ttl_seconds=max(1.0, self.transition_map_cache_ttl_seconds),
        )
        return loaded

    def _load_role_map(self, tenant_id: Optional[str] = None) -> Optional[JiraRoleMap]:
        effective_tenant = self._cache_tenant(tenant_id)
        cache_key = (
            effective_tenant,
            os.path.abspath(self.role_map_path),
            file_fingerprint(self.role_map_path),
        )
        hit, cached = _ROLE_MAP_CACHE.get(cache_key)
        if hit:
            incr("cache_role_map_hit", tenant_id=effective_tenant)
            return cached
        incr("cache_role_map_miss", tenant_id=effective_tenant)
        try:
            loaded = self._call_with_timeout(
                "policy_registry",
                load_role_map,
                self.policy_timeout_seconds,
                self.role_map_path,
            )
        except TimeoutError:
            raise
        except FileNotFoundError:
            self._log_event(
                "warning",
                event="jira.transition.config.role_map_missing",
                tenant_id=effective_tenant,
                decision_id="pending",
                request_id="n/a",
                issue_key="n/a",
                transition_id="n/a",
                repo="n/a",
                pr_number=None,
                mode="strict" if self.strict_mode else "permissive",
                result="ERROR",
                reason_code="CONFIG_MISSING",
                error_code="ROLE_MAP_NOT_FOUND",
                config_path=self.role_map_path,
            )
            return None
        except Exception as exc:
            self._log_event(
                "warning",
                event="jira.transition.config.role_map_invalid",
                tenant_id=effective_tenant,
                decision_id="pending",
                request_id="n/a",
                issue_key="n/a",
                transition_id="n/a",
                repo="n/a",
                pr_number=None,
                mode="strict" if self.strict_mode else "permissive",
                result="ERROR",
                reason_code="CONFIG_INVALID",
                error_code="ROLE_MAP_LOAD_FAILED",
                config_path=self.role_map_path,
                error=str(exc),
            )
            return None
        _ROLE_MAP_CACHE.set(
            cache_key,
            loaded,
            ttl_seconds=max(1.0, self.role_map_cache_ttl_seconds),
        )
        return loaded

    def _effective_strict_mode(self, mode_hint: Optional[str], *, default: bool) -> bool:
        if mode_hint == "strict":
            return True
        if mode_hint == "permissive":
            return False
        return default

    def _resolve_role(self, req: TransitionCheckRequest, tenant_id: Optional[str] = None) -> str:
        """
        Resolve ReleaseGate role from context overrides + Jira role map.
        Returns one of admin/operator/auditor/read_only.
        """
        effective_tenant = self._cache_tenant(tenant_id or req.tenant_id or req.context_overrides.get("tenant_id"))
        role_map = self._load_role_map(tenant_id=effective_tenant)
        if not role_map:
            return "read_only"

        actor_groups = stable_tuple(req.context_overrides.get("jira_groups") or [])
        actor_project_roles = stable_tuple(req.context_overrides.get("jira_project_roles") or [])
        principal_id = str(req.actor_account_id or req.actor_email or "unknown").strip().lower()
        role_map_hash = self._role_map_hash(role_map)
        resolution_key = (
            effective_tenant,
            role_map_hash,
            principal_id,
            actor_groups,
            actor_project_roles,
        )
        hit, cached = _ROLE_RESOLUTION_CACHE.get(resolution_key)
        if hit:
            incr("cache_role_resolution_hit", tenant_id=effective_tenant)
            return str(cached)
        incr("cache_role_resolution_miss", tenant_id=effective_tenant)

        actor_groups_set = {group.lower() for group in actor_groups}
        actor_project_roles_set = {role.lower() for role in actor_project_roles}

        resolved_role = "read_only"
        for role_name in ["admin", "operator", "auditor", "read_only"]:
            resolver = role_map.roles.get(role_name)
            if resolver is None:
                continue
            expected_groups = {group.lower() for group in resolver.jira_groups}
            expected_project_roles = {project_role.lower() for project_role in resolver.jira_project_roles}
            if actor_groups_set.intersection(expected_groups) or actor_project_roles_set.intersection(expected_project_roles):
                resolved_role = role_name
                break

        _ROLE_RESOLUTION_CACHE.set(
            resolution_key,
            resolved_role,
            ttl_seconds=max(1.0, self.role_resolution_cache_ttl_seconds),
        )
        return resolved_role

    def _current_policy_hash(self, tenant_id: Optional[str] = None) -> str:
        if self._policy_hash_cache:
            return self._policy_hash_cache

        effective_tenant = self._cache_tenant(tenant_id)
        compiled_map = self._compiled_policy_map(tenant_id=effective_tenant)
        bindings = self._build_policy_bindings(sorted(compiled_map.keys()), compiled_map, tenant_id=effective_tenant)
        self._policy_hash_cache = self._policy_bindings_hash(bindings)
        return self._policy_hash_cache

    def _compiled_policy_map(self, tenant_id: Optional[str] = None) -> Dict[str, Policy]:
        effective_tenant = self._cache_tenant(tenant_id)
        policy_dir = "releasegate/policy/compiled"
        cache_key = (
            effective_tenant,
            os.path.abspath(policy_dir),
            yaml_tree_fingerprint(policy_dir),
        )
        hit, cached = _POLICY_REGISTRY_CACHE.get(cache_key)
        if hit:
            incr("cache_policy_registry_hit", tenant_id=effective_tenant)
            return dict(cached)
        incr("cache_policy_registry_miss", tenant_id=effective_tenant)

        loader = PolicyLoader(policy_dir=policy_dir, schema="compiled", strict=False)
        policies = self._call_with_timeout(
            "policy_registry",
            loader.load_all,
            self.policy_timeout_seconds,
        )

        compiled: Dict[str, Policy] = {}
        for policy in policies:
            if isinstance(policy, Policy):
                compiled[policy.policy_id] = policy
        _POLICY_REGISTRY_CACHE.set(
            cache_key,
            dict(compiled),
            ttl_seconds=max(1.0, self.policy_registry_cache_ttl_seconds),
        )
        return compiled

    def _policy_hash_for_dict(self, policy_dict: Dict[str, Any]) -> str:
        canonical = json.dumps(policy_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _build_policy_bindings(
        self,
        policy_ids: List[str],
        policy_map: Dict[str, Policy],
        tenant_id: Optional[str] = None,
    ) -> List[PolicyBinding]:
        bindings: List[PolicyBinding] = []
        effective_tenant = resolve_tenant_id(tenant_id)
        seen: set[str] = set()
        for policy_id in policy_ids:
            if policy_id in seen:
                continue
            seen.add(policy_id)
            policy = policy_map.get(policy_id)
            if not policy:
                continue
            policy_dict = policy.model_dump(mode="json", exclude_none=True)
            policy_hash = self._policy_hash_for_dict(policy_dict)
            bindings.append(
                PolicyBinding(
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    policy_hash=policy_hash,
                    tenant_id=effective_tenant,
                    policy=policy_dict,
                )
            )
        return bindings

    def _policy_bindings_hash(self, bindings: List[PolicyBinding]) -> str:
        if not bindings:
            return hashlib.sha256(b"[]").hexdigest()
        material = []
        for binding in sorted(bindings, key=lambda b: b.policy_id):
            material.append(
                {
                    "policy_id": binding.policy_id,
                    "policy_version": binding.policy_version,
                    "policy_hash": binding.policy_hash,
                }
            )
        payload = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _parse_iso_datetime(self, value: Any) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            if raw.endswith("Z"):
                raw = f"{raw[:-1]}+00:00"
            try:
                dt = datetime.fromisoformat(raw)
            except ValueError:
                return None
        else:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _principal_set(self, *values: Any) -> set[str]:
        principals: set[str] = set()
        for value in values:
            if value is None:
                continue
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    normalized = str(item).strip().lower()
                    if normalized:
                        principals.add(normalized)
                continue
            normalized = str(value).strip().lower()
            if normalized:
                principals.add(normalized)
        return principals

    def _call_with_timeout(
        self,
        dependency: str,
        fn: Callable[..., T],
        timeout_seconds: float,
        *args: Any,
        **kwargs: Any,
    ) -> T:
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(fn, *args, **kwargs)
        try:
            result = future.result(timeout=max(timeout_seconds, 0.1))
            pool.shutdown(wait=True, cancel_futures=False)
            return result
        except FutureTimeout as exc:
            future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            raise TimeoutError(f"{dependency} timed out after {timeout_seconds:.2f}s") from exc
        except Exception:
            pool.shutdown(wait=False, cancel_futures=True)
            raise

    def _record_with_timeout(
        self,
        decision: Decision,
        *,
        repo: str,
        pr_number: Optional[int],
        tenant_id: str,
        strict_mode: bool,
        dependency_context: str,
    ) -> Decision:
        try:
            return self._call_with_timeout(
                dependency_context,
                AuditRecorder.record_with_context,
                self.storage_timeout_seconds,
                decision,
                repo=repo,
                pr_number=pr_number,
                tenant_id=tenant_id,
            )
        except TimeoutError:
            fallback_status = DecisionType.BLOCKED if strict_mode else DecisionType.SKIPPED
            fallback_reason_code = "TIMEOUT_DEPENDENCY" if strict_mode else "SKIPPED_TIMEOUT"
            fallback_message = (
                f"BLOCKED: dependency timeout while persisting decision ({dependency_context})"
                if strict_mode
                else f"SKIPPED: dependency timeout while persisting decision ({dependency_context})"
            )
            fallback_id_seed = {
                "version": 1,
                "prior_decision_id": decision.decision_id,
                "dependency_context": dependency_context,
                "fallback": "persist_timeout",
            }
            return decision.model_copy(
                update={
                    "decision_id": hashlib.sha256(canonicalize_json_bytes(fallback_id_seed)).hexdigest(),
                    "timestamp": datetime.now(timezone.utc),
                    "release_status": fallback_status,
                    "message": fallback_message,
                    "reason_code": fallback_reason_code,
                    "unlock_conditions": ["Retry transition after storage dependency recovers."],
                    "inputs_present": {**(decision.inputs_present or {}), "storage_available": False},
                }
            )

    def _dependency_timeout_response(
        self,
        request: TransitionCheckRequest,
        *,
        dependency: str,
        evaluation_key: str,
        repo: str,
        pr_number: Optional[int],
        tenant_id: str,
        strict_mode: bool,
        detail: str,
    ) -> TransitionCheckResponse:
        timeout_status = DecisionType.BLOCKED if strict_mode else DecisionType.SKIPPED
        reason_code = "TIMEOUT_DEPENDENCY" if strict_mode else "SKIPPED_TIMEOUT"
        message = (
            f"BLOCKED: dependency timeout ({dependency})"
            if strict_mode
            else f"SKIPPED: dependency timeout ({dependency})"
        )
        decision = self._build_decision(
            request,
            release_status=timeout_status,
            message=message,
            evaluation_key=f"{evaluation_key}:timeout:{dependency}",
            unlock_conditions=[f"Retry transition after {dependency} dependency recovers."],
            reason_code=reason_code,
            inputs_present={"releasegate_risk": False},
            policy_hash=self._current_policy_hash(),
            input_snapshot={"request": request.model_dump(mode="json"), "timeout": {"dependency": dependency, "detail": detail}},
        )
        final_decision = self._record_with_timeout(
            decision,
            repo=repo,
            pr_number=pr_number,
            tenant_id=tenant_id,
            strict_mode=strict_mode,
            dependency_context="storage",
        )
        self._log_decision(
            event="jira.transition.dependency_timeout",
            request=request,
            decision=final_decision,
            repo=repo,
            pr_number=pr_number,
            mode=strict_mode,
            gate=self._resolved_gate_hint,
            error_code=reason_code,
            dependency=dependency,
        )
        self._track_status_metrics(final_decision.release_status, tenant_id=tenant_id)
        return TransitionCheckResponse(
            allow=final_decision.release_status != DecisionType.BLOCKED,
            reason=final_decision.message,
            decision_id=final_decision.decision_id,
            status=final_decision.release_status.value,
            reason_code=final_decision.reason_code,
            unlock_conditions=final_decision.unlock_conditions,
            policy_hash=final_decision.policy_bundle_hash,
            tenant_id=tenant_id,
        )

    def _log_event(self, level: str, **payload: Any) -> None:
        payload.setdefault("component", "jira_workflow_gate")
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        method = getattr(logger, level, logger.info)
        method(json.dumps(payload, sort_keys=True, default=str))

    def _log_decision(
        self,
        *,
        event: str,
        request: TransitionCheckRequest,
        decision: Decision,
        repo: str,
        pr_number: Optional[int],
        mode: bool,
        gate: Optional[str],
        result: Optional[str] = None,
        policy_bundle_hash: Optional[str] = None,
        error_code: Optional[str] = None,
        dependency: Optional[str] = None,
    ) -> None:
        request_id = (
            request.context_overrides.get("delivery_id")
            or request.context_overrides.get("idempotency_key")
            or self._compute_key(request, tenant_id=decision.tenant_id)[:16]
        )
        self._log_event(
            "info" if not error_code else "error",
            event=event,
            tenant_id=decision.tenant_id,
            decision_id=decision.decision_id,
            request_id=request_id,
            issue_key=request.issue_key,
            transition_id=request.transition_id,
            repo=repo,
            pr_number=pr_number,
            mode="strict" if mode else "permissive",
            result=result or decision.release_status.value,
            reason_code=decision.reason_code,
            policy_bundle_hash=policy_bundle_hash or decision.policy_bundle_hash,
            gate=gate,
            error_code=error_code,
            dependency=dependency,
        )

    def _track_status_metrics(self, status: DecisionType, *, tenant_id: str) -> None:
        if status == DecisionType.BLOCKED:
            incr("transitions_blocked", tenant_id=tenant_id)
        if status == DecisionType.SKIPPED:
            incr("skipped_count", tenant_id=tenant_id)

    def _error_response(
        self,
        request: TransitionCheckRequest,
        *,
        evaluation_key: str,
        repo: str,
        pr_number: Optional[int],
        tenant_id: str,
        message: str,
        reason_code: str,
        strict_mode: bool,
        error_code: str,
    ) -> TransitionCheckResponse:
        fallback_status = DecisionType.ERROR
        fallback_decision = self._build_decision(
            request,
            release_status=fallback_status,
            message=message,
            evaluation_key=f"{evaluation_key}:error",
            unlock_conditions=["Retry transition after resolving ReleaseGate system errors."],
            reason_code=reason_code,
            inputs_present={"releasegate_risk": False},
            policy_hash=self._current_policy_hash(),
            input_snapshot={"request": request.model_dump(mode="json")},
        )
        final_fallback = self._record_with_timeout(
            fallback_decision,
            repo=repo,
            pr_number=pr_number,
            tenant_id=tenant_id,
            strict_mode=strict_mode,
            dependency_context="storage",
        )
        self._log_decision(
            event="jira.transition.error_response",
            request=request,
            decision=final_fallback,
            repo=repo,
            pr_number=pr_number,
            mode=strict_mode,
            gate=self._resolved_gate_hint,
            error_code=error_code,
        )
        incr("transitions_error", tenant_id=tenant_id)
        should_block = strict_mode or request.environment.upper() == "PRODUCTION"
        if should_block:
            incr("transitions_blocked", tenant_id=tenant_id)
        return TransitionCheckResponse(
            allow=not should_block,
            reason=final_fallback.message,
            decision_id=final_fallback.decision_id,
            status=fallback_status.value,
            reason_code=final_fallback.reason_code,
            policy_hash=final_fallback.policy_bundle_hash,
            tenant_id=tenant_id,
        )

    def _repo_and_pr(self, request: TransitionCheckRequest) -> tuple[str, Optional[int]]:
        repo = request.context_overrides.get("repo", "unknown")
        pr_number = request.context_overrides.get("pr_number")
        try:
            pr = int(pr_number) if pr_number is not None else None
        except Exception:
            pr = None
        return repo, pr

    def _fetch_risk_metadata_from_ci(self, *, repo: str, pr_number: Optional[int]) -> Dict[str, Any]:
        if not repo or repo == "unknown" or pr_number is None:
            return {}

        github_token = (os.getenv("GITHUB_TOKEN") or "").strip()
        if not github_token:
            return {}

        url = f"https://api.github.com/repos/{repo}/pulls/{int(pr_number)}"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }
        tenant_id = self._active_tenant_id or "default"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=max(self.ci_score_timeout_seconds, 0.1),
            )
        except requests.RequestException as exc:
            self._log_event(
                "warning",
                event="jira.transition.risk_fallback.request_failed",
                tenant_id=tenant_id,
                decision_id="pending",
                request_id="ci-score",
                issue_key="unknown",
                transition_id="unknown",
                repo=repo,
                pr_number=pr_number,
                mode="unknown",
                result="PENDING",
                reason_code="GITHUB_PR_FETCH_FAILED",
                policy_bundle_hash=self._current_policy_hash(),
                error=str(exc),
            )
            return {}

        if response.status_code != 200:
            self._log_event(
                "warning",
                event="jira.transition.risk_fallback.http_error",
                tenant_id=tenant_id,
                decision_id="pending",
                request_id="ci-score",
                issue_key="unknown",
                transition_id="unknown",
                repo=repo,
                pr_number=pr_number,
                mode="unknown",
                result="PENDING",
                reason_code="GITHUB_PR_FETCH_HTTP_ERROR",
                policy_bundle_hash=self._current_policy_hash(),
                status_code=response.status_code,
            )
            return {}

        try:
            pr_data = response.json() or {}
        except ValueError:
            return {}

        metrics = PRRiskInput(
            changed_files=int(pr_data.get("changed_files", 0) or 0),
            additions=int(pr_data.get("additions", 0) or 0),
            deletions=int(pr_data.get("deletions", 0) or 0),
        )
        risk_level = classify_pr_risk(metrics)
        return build_issue_risk_property(
            repo=repo,
            pr_number=int(pr_number),
            risk_level=risk_level,
            metrics=metrics,
            source="github",
        )

    def _strict_dependency_failure(
        self,
        *,
        repo: str,
        pr_number: Optional[int],
    ) -> Optional[tuple[str, str, List[str]]]:
        """
        Return a fail-closed reason tuple when strict mode dependency truth cannot
        be established for an explicitly provided repo/PR context.
        """
        if not repo or repo == "unknown" or pr_number is None:
            return None

        if repo.count("/") != 1 or any(not part.strip() for part in repo.split("/", 1)):
            return (
                "INVALID_REPO_CONTEXT",
                "BLOCKED: invalid repository context for strict mode",
                ["Provide repo in OWNER/REPO format."],
            )
        if int(pr_number) <= 0:
            return (
                "INVALID_PR_NUMBER",
                "BLOCKED: invalid PR number for strict mode",
                ["Provide a positive pull request number."],
            )

        github_token = (os.getenv("GITHUB_TOKEN") or "").strip()
        if not github_token:
            return (
                "GITHUB_AUTH_FAILED",
                "BLOCKED: GitHub token is required for strict mode validation",
                ["Set GITHUB_TOKEN with read access to the configured repository."],
            )

        url = f"https://api.github.com/repos/{repo}/pulls/{int(pr_number)}"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }
        timeout = max(self.ci_score_timeout_seconds, 0.1)
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            self._log_event(
                "warning",
                event="jira.transition.strict_dependency.request_failed",
                tenant_id=self._active_tenant_id or "default",
                decision_id="pending",
                request_id="strict-dependency",
                issue_key="unknown",
                transition_id="unknown",
                repo=repo,
                pr_number=pr_number,
                mode="strict",
                result="PENDING",
                reason_code="GITHUB_UNAVAILABLE",
                policy_bundle_hash=self._current_policy_hash(),
                error=str(exc),
            )
            return (
                "GITHUB_UNAVAILABLE",
                "BLOCKED: GitHub dependency unavailable in strict mode",
                ["Retry after GitHub API connectivity recovers."],
            )

        if response.status_code == 200:
            return None
        if response.status_code == 404:
            return (
                "REPO_OR_PR_NOT_FOUND",
                f"BLOCKED: repository or pull request not found ({repo}#{int(pr_number)})",
                ["Use a valid repository and pull request mapping for this transition."],
            )
        if response.status_code in {401, 403}:
            return (
                "GITHUB_AUTH_FAILED",
                "BLOCKED: GitHub authentication/authorization failed in strict mode",
                ["Fix GitHub token permissions for repository and pull request access."],
            )

        return (
            "GITHUB_UNAVAILABLE",
            f"BLOCKED: GitHub PR lookup failed with status {response.status_code}",
            ["Retry after GitHub API dependency recovers."],
        )

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
        policy_bindings: Optional[List[PolicyBinding]] = None,
        input_snapshot: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        repo, pr_number = self._repo_and_pr(request)
        tenant_id = self._tenant_id(request)
        effective_policy_bindings = list(policy_bindings or [])
        for binding in effective_policy_bindings:
            if not binding.tenant_id:
                binding.tenant_id = tenant_id
        decision_id = str(evaluation_key)
        return Decision(
            decision_id=decision_id,
            tenant_id=tenant_id,
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
            input_snapshot=input_snapshot or {},
            policy_bindings=effective_policy_bindings,
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
