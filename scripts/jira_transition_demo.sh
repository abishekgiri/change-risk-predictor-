#!/bin/bash
# Demo: Simulate a Jira Webhook Call

echo "Simulating Jira Transition Check..." >&2

curl -sS --max-time 10 -X POST "http://127.0.0.1:8001/integrations/jira/transition/check" \
  -H "Content-Type: application/json" \
  -d '{
    "issue_key": "PROJ-123",
    "transition_id": "31",
    "transition_name": "Read for Prod",
    "source_status": "Open",
    "target_status": "Ready for Deploy",
    "actor_account_id": "557058:be8b47b4-3b2d-4b1e-8f28-56789abcdef",
    "environment": "PRODUCTION",
    "project_key": "PROJ",
    "issue_type": "Story"
  }' | jq
