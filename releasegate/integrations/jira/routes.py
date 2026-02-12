from fastapi import APIRouter, HTTPException
from releasegate.integrations.jira.types import TransitionCheckRequest, TransitionCheckResponse
from releasegate.integrations.jira.workflow_gate import WorkflowGate
from releasegate.integrations.jira.client import JiraClient
from releasegate.observability.internal_metrics import snapshot as metrics_snapshot
from releasegate.security.auth import require_access
from releasegate.security.types import AuthContext

router = APIRouter()

@router.post("/transition/check", response_model=TransitionCheckResponse)
async def check_transition(
    request: TransitionCheckRequest,
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
    gate = WorkflowGate()
    return gate.check_transition(request)

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
