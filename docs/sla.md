# Service Level Objectives (SLA Targets)

These targets define expected behavior for governance enforcement and anchoring operations.

## Availability

- Enforcement availability target: **99.9% monthly**
- Availability is measured as: successful policy decision responses / total decision requests

## Decision Latency

- `p50 < 150ms`
- `p95 < 400ms`
- `p99 < 1s`

## Anchoring Durability

- Anchoring RPO: **<= 1 hour**
- Anchoring RTO: **<= 4 hours**

## Outage Behavior

When policy control-plane access fails:

1. Use cached policy snapshot if still within TTL.
2. Use stale cached snapshot only within grace window.
3. If cache is expired and grace has elapsed, fail closed (block).

If fail-open mode is explicitly enabled for allowlisted scopes, degraded fail-open behavior is permitted and must be audited.

## Incident Communication

- P1 incident response starts within 15 minutes.
- Status updates are posted at least every 30 minutes until mitigation.

## Metrics Tie-In

Track and report the following from the observability layer:

- Integrity score trend
- Drift index trend
- Override rate trend
- Block frequency trend

Use these metrics to confirm SLA health and detect outage-induced regressions.
