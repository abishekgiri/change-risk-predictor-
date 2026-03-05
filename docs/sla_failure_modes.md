# SLA Failure Modes

This document defines enforcement behavior during partial outages so operators can answer: "what happens if the system goes down?"

## Runtime Defaults

- `RELEASEGATE_FAIL_MODE=closed` (default)
- `RELEASEGATE_FAIL_OPEN_ALLOWLIST=` (empty by default)
- `RELEASEGATE_POLICY_SNAPSHOT_CACHE_TTL_SECONDS=900`
- `RELEASEGATE_POLICY_GRACE_WINDOW_SECONDS=300`

## Failure Mode Matrix

| Failure | Behavior | Max Duration | Audit Signal |
| --- | --- | --- | --- |
| Policy control-plane lookup fails and cache is fresh | Reuse cached policy snapshot and continue enforcement | `TTL` | `policy.snapshot.cache_hit` |
| Policy control-plane lookup fails and cache is stale but in grace | Reuse cached policy snapshot in degraded mode | `TTL + grace window` | `policy.snapshot.cache_stale_grace_used` |
| Policy control-plane lookup fails and cache is expired | Fail closed (block transition) | Immediate | `policy.snapshot.cache_expired_fail_closed` |
| Fail-open mode enabled and scope allowlisted | Return empty effective policy (degraded fail-open) | Until outage resolves | `policy.snapshot.cache_expired_fail_open` |

## Policy Snapshot Cache

Snapshot cache rows are stored in `tenant_policy_snapshot_cache`:

- `tenant_id`
- `scope_key`
- `snapshot_hash`
- `snapshot_json`
- `resolved_at`
- `ttl_seconds`
- `source`

`scope_key` is derived from `(org_id, project_id, workflow_id, transition_id, rollout_key, status_filter)` to keep fallback deterministic.

## Fail-Closed vs Fail-Open

- **Fail-closed** is default and recommended for production.
- **Fail-open** is only allowed when:
  - `RELEASEGATE_FAIL_MODE=open`
  - `RELEASEGATE_FAIL_OPEN_ALLOWLIST` contains either `*` or the exact `scope_key`.

## Emergency Override Protocol

Break-glass override requests must include:

- explicit actor identity
- human-readable justification
- strict TTL
- immutable audit trail

Use existing override APIs and security audit events to document each break-glass action.
