# Demo Scenarios

This file defines a short customer demo script for enterprise walkthroughs.

## Scenario 1: High-Risk Transition Block

1. Open Jira issue `PAYMENTS-321`.
2. Mark issue as high risk (`risk:high`).
3. Attempt transition `Ready for Release -> Done`.
4. Expected result: transition blocked.

Expected explanation output:

- Status: `BLOCKED`
- Reason code: `HIGH_RISK_APPROVAL_REQUIRED`
- Unlock condition: provide required approvals

## Scenario 2: Controlled Override

1. Use same issue after block.
2. Submit manual override with reason and TTL.
3. Re-run transition check.
4. Expected result: conditional/allowed based on override policy.

Expected dashboard evidence:

- Decision appears in Observability drilldown
- Override appears in Overrides table
- Decision explainer links to policy and evidence context

## Scenario 3: Activation Rollback

1. Move onboarding mode from `simulation -> canary -> strict`.
2. Trigger rollback from onboarding panel.
3. Expected result: mode reverts to previous state with history entry.

## Scenario 4: Tenant Quota Visibility

1. Open Billing page.
2. Review decision/override/storage usage against plan limits.
3. Show plan-tier implications for simulation history and volume limits.
