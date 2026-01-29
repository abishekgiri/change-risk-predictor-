from fastapi import APIRouter, HTTPException, Header
from releasegate.integrations.jira.types import TransitionCheckRequest, TransitionCheckResponse
from releasegate.integrations.jira.workflow_gate import WorkflowGate
from releasegate.integrations.jira.client import JiraClient

router = APIRouter()

@router.post("/transition/check", response_model=TransitionCheckResponse)
async def check_transition(request: TransitionCheckRequest):
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

