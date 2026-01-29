# Phase 10: Jira Workflow Enforcement

**Status**: ✅ Released in v0.2.0

## Overview
Phase 10 introduces the **Jira Workflow Gate**, a blocking enforcement mechanism that sits between Jira transitions and the ReleaseGate decision engine. This allows teams to prevent risky changes from moving to production (e.g., "In Review" -> "Ready for Prod") unless they satisfy all governance policies.

## Architecture

### 1. The Workflow Gate (`workflow_gate.py`)
Intercepts Jira Webhooks and performs the following:
1.  **Idempotency Check**: Uses a stable hash (`issue_key + transition_id + source_status + target_status`) to ensure duplicate webhook events don't trigger redundant checks.
2.  **Context Construction**: Maps Jira metadata (user, project, env) into the ReleaseGate `EvaluationContext` format.
    *   *Note*: In Phase 10 MVP, PR signals (`files_changed`, `churn`) are defaulted to safe values if not linked.
3.  **Policy Resolution**: Loads `jira_transition_map.yaml` to determine which policies apply to the specific transition.
4.  **Engine Evaluation**: Invokes the `ComplianceEngine` to render a decision (`ALLOWED`, `BLOCKED`, or `CONDITIONAL`).
5.  **Audit Logging**: Persists the decision to SQLite with a unique UUID.

### 2. API Contract
**Endpoint**: `POST /integrations/jira/transition/check`

**Request Payload**:
```json
{
  "issue_key": "PROJ-123",
  "transition_id": "31",
  "source_status": "Open",
  "target_status": "Ready for Prod",
  "environment": "PRODUCTION",
  "actor_account_id": "557058:..."
}
```

**Response Payload**:
```json
{
  "allow": false,
  "status": "BLOCKED",
  "decision_id": "uuid-...",
  "reason": "Policy Check: BLOCKED",
  "requirements": ["Need approval", "Critical Path detected"],
  "unlock_conditions": ["Need approval", "Critical Path detected"]
}
```

### 3. Fail-Safe Behavior
- **Production**: Fail Closed (Block on system error).
- **Non-Prod**: Fail Open (Allow on system error, log exception).

## Configuration

### Policy Mapping (`releasegate/integrations/jira/jira_transition_map.yaml`)
Maps Jira environments and transitions to Policy IDs.

```yaml
PRODUCTION:
  DEFAULT:
    # Transition ID 31 (Ready for Prod) checks p1 (Approvals) and p2 (SFA)
    "31": ["p1", "p2"] 
```

### Role Mapping (`releasegate/integrations/jira/jira_role_map.yaml`)
(Placeholder) Maps Jira Groups to internal Roles (e.g., "jira-administrators" -> "Maintainer").

## Usage
To simulate a transition check:

```bash
bash scripts/jira_transition_demo.sh | jq .
```
