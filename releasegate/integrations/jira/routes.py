from __future__ import annotations

import json
import logging
from typing import List

from fastapi import APIRouter, Header, HTTPException
from releasegate.integrations.jira.lock_store import (
    apply_transition_lock_update,
    expire_override_if_needed,
)
from releasegate.audit.idempotency import (
    cancel_idempotency_claim,
    claim_idempotency,
    complete_idempotency,
    derive_system_idempotency_key,
    wait_for_idempotency_response,
)
from releasegate.integrations.jira.decision_linkage import (
    build_context_payload,
    compute_context_hash,
    is_protected_status,
    register_transition_decision_link,
    validate_and_consume_decision_link,
)
from releasegate.integrations.jira.types import (
    TransitionAuthorizeRequest,
    TransitionAuthorizeResponse,
    TransitionCheckRequest,
    TransitionCheckResponse,
)
from releasegate.integrations.jira.workflow_gate import WorkflowGate
from releasegate.integrations.jira.client import JiraClient
from releasegate.integrations.jira.override_validation import (
    ACTION_OVERRIDE,
    validate_override_request,
)
from releasegate.observability.internal_metrics import snapshot as metrics_snapshot
from releasegate.quota import QUOTA_KIND_DECISIONS, TenantQuotaExceededError, consume_tenant_quota
from releasegate.security.auth import require_access
from releasegate.security.anomaly_detector import record_anomaly_event
from releasegate.security.rate_limit import enforce_issue_rate_limit
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.security.types import AuthContext
from releasegate.utils.canonical import sha256_json

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/transition/check", response_model=TransitionCheckResponse)
async def check_transition(
    request: TransitionCheckRequest,
    x_idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    x_atlassian_webhook_identifier: str | None = Header(default=None, alias="X-Atlassian-Webhook-Identifier"),
    x_request_id: str | None = Header(default=None, alias="X-Request-Id"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
    x_webhook_delivery: str | None = Header(default=None, alias="X-Webhook-Delivery"),
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        allow_signature=True,
        rate_profile="webhook",
    ),
):
    """
    Webhook target for Jira Automation.
    Returns:
      200 OK with allow=true/false
    """
    tenant_id = resolve_tenant_id(request.tenant_id or auth.tenant_id or request.context_overrides.get("tenant_id"))
    request.tenant_id = tenant_id
    enforce_issue_rate_limit(tenant_id=tenant_id, issue_key=request.issue_key, profile="webhook")

    # Best-effort: clear expired overrides before evaluating this transition.
    try:
        expire_override_if_needed(
            tenant_id=tenant_id,
            issue_key=request.issue_key,
            actor=request.actor_email or request.actor_account_id,
        )
    except Exception:
        # Never block the transition gate on lock ledger errors.
        pass

    delivery_id = (
        x_atlassian_webhook_identifier
        or x_request_id
        or x_github_delivery
        or x_webhook_delivery
        or request.context_overrides.get("delivery_id")
    )
    operation = "jira_transition_check"
    idem_key = (
        x_idempotency_key
        or request.context_overrides.get("idempotency_key")
        or (
            derive_system_idempotency_key(
                tenant_id=tenant_id,
                operation=operation,
                identity={
                    "integration_id": auth.integration_id or "jira",
                    "delivery_id": delivery_id,
                },
            )
            if delivery_id
            else derive_system_idempotency_key(
                tenant_id=tenant_id,
                operation=operation,
                identity={
                    "integration_id": auth.integration_id or "jira",
                    "issue_key": request.issue_key,
                    "transition_id": request.transition_id,
                    "source_status": request.source_status,
                    "target_status": request.target_status,
                    "environment": request.environment,
                    "actor_account_id": request.actor_account_id,
                },
            )
        )
    )

    request.context_overrides = {
        **request.context_overrides,
        "idempotency_key": idem_key,
    }
    if delivery_id:
        request.context_overrides["delivery_id"] = delivery_id

    override_requested = bool(request.context_overrides.get("override") is True)
    if override_requested:
        validation = validate_override_request(
            action=ACTION_OVERRIDE,
            ttl_seconds=request.context_overrides.get("override_ttl_seconds"),
            justification=request.context_overrides.get("override_reason"),
            actor_roles=auth.roles,
            idempotency_key=idem_key,
        )
        if not validation.allowed:
            status_code = 403 if validation.reason_code == "OVERRIDE_ADMIN_REQUIRED" else 400
            try:
                record_anomaly_event(
                    tenant_id=tenant_id,
                    signal_type="failed_override_attempt",
                    operation="jira_transition_check",
                    details={
                        "reason_code": validation.reason_code,
                        "status_code": status_code,
                        "issue_key": request.issue_key,
                    },
                    actor=auth.principal_id,
                )
            except Exception:
                pass
            raise HTTPException(
                status_code=status_code,
                detail={
                    "error_code": validation.reason_code,
                    "message": validation.message,
                },
            )
        request.context_overrides = {
            **request.context_overrides,
            "override_ttl_seconds": validation.ttl_seconds,
            "override_expires_at": validation.expires_at,
            "override_reason": validation.justification,
            # Explicitly server-derived, never trusted from client payload.
            "override_expires_at_server_derived": True,
        }

    request_id = delivery_id or idem_key
    logger.info(
        json.dumps(
            {
                "event": "jira.transition.request.received",
                "component": "jira_routes",
                "tenant_id": tenant_id,
                "decision_id": "pending",
                "request_id": request_id,
                "issue_key": request.issue_key,
                "transition_id": request.transition_id,
                "result": "PENDING",
                "reason_code": "PENDING",
            },
            sort_keys=True,
        )
    )

    try:
        claim = claim_idempotency(
            tenant_id=tenant_id,
            operation=operation,
            idem_key=idem_key,
            request_payload=request.model_dump(mode="json"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if claim.state == "replay" and claim.response is not None:
        replay = TransitionCheckResponse.model_validate(claim.response)
        logger.info(
            json.dumps(
                {
                    "event": "jira.transition.request.replay",
                    "component": "jira_routes",
                    "tenant_id": tenant_id,
                    "decision_id": replay.decision_id,
                    "request_id": request_id,
                    "issue_key": request.issue_key,
                    "transition_id": request.transition_id,
                    "result": replay.status,
                    "reason_code": "IDEMPOTENT_REPLAY",
                    "policy_bundle_hash": replay.policy_hash,
                },
                sort_keys=True,
            )
        )
        # Best-effort: keep Jira lock state consistent with the replayed response.
        _apply_jira_lock_best_effort(request, replay, tenant_id=tenant_id)
        return replay
    if claim.state == "in_progress":
        replayed = wait_for_idempotency_response(
            tenant_id=tenant_id,
            operation=operation,
            idem_key=idem_key,
        )
        if replayed is not None:
            modeled = TransitionCheckResponse.model_validate(replayed)
            _apply_jira_lock_best_effort(request, modeled, tenant_id=tenant_id)
            return modeled
        raise HTTPException(status_code=409, detail="Idempotent request is still in progress")

    try:
        consume_tenant_quota(
            tenant_id=tenant_id,
            quota_kind=QUOTA_KIND_DECISIONS,
            amount=1,
        )
    except TenantQuotaExceededError as exc:
        cancel_idempotency_claim(
            tenant_id=tenant_id,
            operation=operation,
            idem_key=idem_key,
        )
        try:
            record_anomaly_event(
                tenant_id=tenant_id,
                signal_type="quota_bypass_attempt",
                operation=operation,
                details=exc.to_http_detail(),
                actor=auth.principal_id,
            )
        except Exception:
            pass
        raise HTTPException(status_code=429, detail=exc.to_http_detail()) from exc

    gate = WorkflowGate()
    response = gate.check_transition(request)
    try:
        register_transition_decision_link(
            tenant_id=tenant_id,
            decision_id=response.decision_id,
            issue_key=request.issue_key,
            transition_id=request.transition_id,
            actor_account_id=request.actor_account_id,
            source_status=request.source_status,
            target_status=request.target_status,
            environment=request.environment,
            project_key=request.project_key,
        )
    except Exception as exc:
        if is_protected_status(request.target_status):
            cancel_idempotency_claim(
                tenant_id=tenant_id,
                operation=operation,
                idem_key=idem_key,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "error_code": "DECISION_LINK_REGISTRATION_FAILED",
                    "message": "Decision linkage registration failed for protected transition.",
                },
            ) from exc
        logger.warning(
            "Decision linkage registration failed for tenant=%s decision=%s issue=%s transition=%s: %s",
            tenant_id,
            response.decision_id,
            request.issue_key,
            request.transition_id,
            exc,
        )
    logger.info(
        json.dumps(
            {
                "event": "jira.transition.request.completed",
                "component": "jira_routes",
                "tenant_id": tenant_id,
                "decision_id": response.decision_id,
                "request_id": request_id,
                "issue_key": request.issue_key,
                "transition_id": request.transition_id,
                "result": response.status,
                "reason_code": "COMPLETED",
                "policy_bundle_hash": response.policy_hash,
            },
            sort_keys=True,
        )
    )
    complete_idempotency(
        tenant_id=tenant_id,
        operation=operation,
        idem_key=idem_key,
        response_payload=response.model_dump(mode="json"),
        resource_type="decision",
        resource_id=response.decision_id,
    )
    _apply_jira_lock_best_effort(request, response, tenant_id=tenant_id)
    return response


@router.post("/transition/authorize", response_model=TransitionAuthorizeResponse)
async def authorize_transition(
    request: TransitionAuthorizeRequest,
    x_request_id: str | None = Header(default=None, alias="X-Request-Id"),
    x_idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    auth: AuthContext = require_access(
        roles=["admin", "operator"],
        scopes=["enforcement:write"],
        allow_signature=True,
        rate_profile="webhook",
    ),
):
    from releasegate.audit.reader import AuditReader

    tenant_id = resolve_tenant_id(request.tenant_id or auth.tenant_id)
    request.tenant_id = tenant_id

    decision_id = str(request.releasegate_decision_id or "").strip()
    if is_protected_status(request.target_status) and not decision_id:
        return TransitionAuthorizeResponse(
            allow=False,
            decision_id=None,
            reason_code="DECISION_ID_REQUIRED",
            message="Protected transitions require releasegate_decision_id.",
            tenant_id=tenant_id,
        )

    if not is_protected_status(request.target_status):
        return TransitionAuthorizeResponse(
            allow=True,
            decision_id=decision_id or None,
            reason_code="NOT_PROTECTED",
            message="Transition target is not protected.",
            tenant_id=tenant_id,
        )

    decision_row = AuditReader.get_decision(decision_id=decision_id, tenant_id=tenant_id)
    if not decision_row:
        return TransitionAuthorizeResponse(
            allow=False,
            decision_id=decision_id,
            reason_code="DECISION_NOT_FOUND",
            message="Referenced decision was not found.",
            tenant_id=tenant_id,
        )

    if str(decision_row.get("release_status") or "").upper() != "ALLOWED":
        return TransitionAuthorizeResponse(
            allow=False,
            decision_id=decision_id,
            reason_code="DECISION_NOT_ALLOWED",
            message="Referenced decision is not ALLOWED.",
            tenant_id=tenant_id,
        )

    expected_context_hash = compute_context_hash(
        build_context_payload(
            tenant_id=tenant_id,
            issue_key=request.issue_key,
            transition_id=request.transition_id,
            actor_account_id=request.actor_account_id,
            source_status=request.source_status,
            target_status=request.target_status,
            environment=request.environment,
            project_key=request.project_key,
        )
    )
    consume_request_id = (
        str(request.request_id or "").strip()
        or str(x_request_id or "").strip()
        or str(x_idempotency_key or "").strip()
        or None
    )
    try:
        with get_storage_backend().transaction():
            ok, reason = validate_and_consume_decision_link(
                tenant_id=tenant_id,
                decision_id=decision_id,
                expected_context_hash=expected_context_hash,
                request_id=consume_request_id,
            )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "DECISION_LINK_CHECK_FAILED",
                "message": f"Decision linkage check failed: {exc}",
            },
        ) from exc

    if not ok:
        return TransitionAuthorizeResponse(
            allow=False,
            decision_id=decision_id,
            reason_code=reason,
            message=f"Protected transition denied ({reason}).",
            tenant_id=tenant_id,
        )
    return TransitionAuthorizeResponse(
        allow=True,
        decision_id=decision_id,
        reason_code=reason,
        message="Protected transition authorized.",
        tenant_id=tenant_id,
    )


def _apply_jira_lock_best_effort(
    request: TransitionCheckRequest,
    response: TransitionCheckResponse,
    *,
    tenant_id: str,
) -> None:
    """
    Keep a durable, append-only lock ledger for Jira issues.

    This is a side-effect; failures are intentionally swallowed so the transition
    evaluation path remains available even if storage is degraded.
    """
    try:
        from releasegate.audit.reader import AuditReader

        row = AuditReader.get_decision(decision_id=response.decision_id, tenant_id=tenant_id)
        policy_hash = None
        policy_resolution_hash = None
        input_hash = None
        evaluation_key = None
        risk_hash = ""
        reason_codes: List[str] = []
        repo = None
        pr_number = None
        decision_id = response.decision_id

        if row:
            repo = row.get("repo")
            pr_number = row.get("pr_number")
            policy_hash = row.get("policy_hash") or row.get("policy_bundle_hash") or response.policy_hash
            policy_resolution_hash = row.get("policy_bundle_hash") or row.get("policy_hash") or response.policy_hash
            input_hash = row.get("input_hash")
            evaluation_key = row.get("evaluation_key")
            raw_full = row.get("full_decision_json")
            if isinstance(raw_full, str) and raw_full:
                try:
                    payload = json.loads(raw_full)
                except Exception:
                    payload = {}
                rc = payload.get("reason_code")
                if rc:
                    reason_codes.append(str(rc))
                signal_map = (
                    ((payload.get("input_snapshot") or {}).get("signal_map") or {})
                    if isinstance(payload, dict)
                    else {}
                )
                risk_payload = signal_map.get("risk") if isinstance(signal_map, dict) else None
                if isinstance(risk_payload, dict) and risk_payload:
                    risk_hash = sha256_json(risk_payload)
        if not reason_codes:
            # Fall back to the response status if we couldn't load the decision.
            reason_codes = [str(response.status)]

        override_requested = bool(request.context_overrides.get("override") is True)
        override_expires_at = None
        override_reason = None
        override_ttl_seconds = None
        override_by = None
        if override_requested and response.allow:
            override_expires_at = request.context_overrides.get("override_expires_at")
            override_reason = request.context_overrides.get("override_reason")
            override_ttl_seconds = request.context_overrides.get("override_ttl_seconds")
            override_by = request.actor_email or request.actor_account_id

        apply_transition_lock_update(
            tenant_id=tenant_id,
            issue_key=request.issue_key,
            desired_locked=not bool(response.allow),
            reason_codes=reason_codes,
            decision_id=decision_id,
            policy_hash=policy_hash,
            policy_resolution_hash=policy_resolution_hash,
            repo=repo,
            pr_number=pr_number,
            actor=request.actor_email or request.actor_account_id,
            override_expires_at=str(override_expires_at) if override_expires_at else None,
            override_reason=str(override_reason) if override_reason else None,
            override_by=str(override_by) if override_by else None,
            ttl_seconds=int(override_ttl_seconds) if override_ttl_seconds is not None else None,
            justification=str(override_reason) if override_reason else None,
            context={
                "transition_id": request.transition_id,
                "source_status": request.source_status,
                "target_status": request.target_status,
                "request_id": request.context_overrides.get("delivery_id")
                or request.context_overrides.get("idempotency_key"),
                "evaluation_key": str(evaluation_key or request.context_overrides.get("idempotency_key") or ""),
                "input_hash": str(input_hash or ""),
                "policy_hash": str(policy_hash or policy_resolution_hash or response.policy_hash or ""),
                "risk_hash": risk_hash,
            },
        )
    except Exception:
        return

@router.get("/health")
async def health_check():
    """
    Verifies credentials and connectivity.
    """
    client = JiraClient()
    if client.check_permissions():
        return {"status": "ok", "service": "jira"}
    raise HTTPException(status_code=503, detail="Jira connectivity failed")


@router.get("/metrics/internal")
async def internal_metrics(
    tenant_id: str | None = None,
    include_tenants: bool = False,
    auth: AuthContext = require_access(
        roles=["admin", "operator", "auditor", "read_only"],
        scopes=["policy:read"],
        rate_profile="default",
    ),
):
    return metrics_snapshot(tenant_id=tenant_id or auth.tenant_id, include_tenants=include_tenants)
