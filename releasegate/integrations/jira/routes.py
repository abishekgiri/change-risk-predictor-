import json
import logging

from fastapi import APIRouter, Header, HTTPException
from releasegate.audit.reader import AuditReader
from releasegate.audit.idempotency import (
    claim_idempotency,
    complete_idempotency,
    derive_system_idempotency_key,
    wait_for_idempotency_response,
)
from releasegate.integrations.jira.types import TransitionCheckRequest, TransitionCheckResponse
from releasegate.integrations.jira.workflow_gate import WorkflowGate
from releasegate.integrations.jira.client import JiraClient
from releasegate.observability.internal_metrics import snapshot as metrics_snapshot
from releasegate.security.auth import require_access
from releasegate.storage.base import resolve_tenant_id
from releasegate.security.types import AuthContext

router = APIRouter()
logger = logging.getLogger(__name__)


def _attach_attestation_id(response: TransitionCheckResponse, *, tenant_id: str) -> TransitionCheckResponse:
    if response.attestation_id:
        return response
    row = AuditReader.get_attestation_by_decision(response.decision_id, tenant_id=tenant_id)
    if row and row.get("attestation_id"):
        return response.model_copy(update={"attestation_id": row["attestation_id"]})
    return response

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
        replay = _attach_attestation_id(
            TransitionCheckResponse.model_validate(claim.response),
            tenant_id=tenant_id,
        )
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
        return replay
    if claim.state == "in_progress":
        replayed = wait_for_idempotency_response(
            tenant_id=tenant_id,
            operation=operation,
            idem_key=idem_key,
        )
        if replayed is not None:
            return _attach_attestation_id(
                TransitionCheckResponse.model_validate(replayed),
                tenant_id=tenant_id,
            )
        raise HTTPException(status_code=409, detail="Idempotent request is still in progress")

    gate = WorkflowGate()
    response = _attach_attestation_id(gate.check_transition(request), tenant_id=tenant_id)
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
    return response

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
