# Signal Freshness Model

## Objective

ReleaseGate uses a zero-trust signal model: decision inputs are accepted only if they are recent, attributable, and policy-allowed.

## Zero-Trust Signal Principles

- Signals are never trusted solely because they exist.
- Every signal is evaluated for freshness and context.
- Expired or missing-required signals produce fail-closed behavior in strict mode.

## Signal Classes

| Signal | Purpose | Typical Source |
| --- | --- | --- |
| Risk score | classify change risk | risk engine / CI pipeline |
| Transition context | workflow gate context | Jira transition request |
| Override metadata | break-glass intent + approval context | override API path |
| Integrity/attestation metadata | trust chain validation | attestation and audit layers |

## TTL Enforcement

Signal validity is bounded by policy-driven TTL windows.

- Example: risk signal TTL = 5 minutes
- if signal age > TTL:
- signal is treated as stale
- strict policies deny transition (fail closed)
- stale events are auditable in security telemetry

## Why TTL Exists

TTL enforcement reduces:

- replay of old approvals/scores
- stale-context decisions during outages
- policy bypass through delayed transitions

## Fail-Closed Freshness Behavior

When required signals are stale or unavailable:

- strict mode: deny
- permissive mode (if configured): may degrade, but still records explicit audit context

This keeps degraded behavior observable and reviewable.

## Separation of Duties (SoD) Controls

ReleaseGate evaluates SoD constraints in the transition/override flow.

Representative constraints:

- requester != approver
- override requestor != override approver
- PR author cannot self-approve emergency override

When SoD conflicts are detected, decisions are blocked with explicit reason codes.

## Auditor Checks

Auditors should verify:

- stale-signal denials appear in decision/explainer traces
- SoD reason codes are present for blocked violations
- override events include actor, approver, reason, and TTL metadata

These checks confirm signal freshness and SoD are enforced as controls, not documentation-only claims.
