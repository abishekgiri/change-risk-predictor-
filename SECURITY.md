# ReleaseGate Security Milestone (Governance Ledger)

This milestone hardens ReleaseGate into a tamper-evident governance system for Jira release controls.

## What Is Chained

ReleaseGate now maintains a dedicated hash-chain for Jira lock events in `jira_lock_events`.

- Chain scope: `tenant_id + chain_id` (for example `jira-lock:RG-1`)
- Event continuity: `prev_hash -> event_hash`
- Sequence continuity: strictly monotonic `seq` per chain
- Event types in chain: `LOCK`, `UNLOCK`, `OVERRIDE`, `OVERRIDE_EXPIRE`
- Canonical input for hash:
  - tenant, chain, seq, issue, action, decision/policy refs
  - TTL/expiry, justification, actor, context
  - canonical JSON (sorted keys, stable separators)

This is independent from the override/transparency chains and is intentionally not merged with them.

## What Is Signed

ReleaseGate signs Jira lock ledger checkpoints (`audit_lock_checkpoints`) and verifies them against live chain replay.

- Signed payload includes:
  - `tenant_id`, `chain_id`, `cadence`, `period_id`, `period_end`
  - `head_seq`, `head_hash`, `event_count`
- Signature metadata includes:
  - algorithm (`HMAC-SHA256`)
  - `signing_key_id`
- Verification checks:
  - signature validity
  - chain validity
  - `head_hash` match
  - `head_seq` match
  - `event_count` match

## What Is Anchored

For this milestone, lock checkpoints are anchored in append-only storage:

- Checkpoint files: deterministic JSON under the checkpoint store
- Checkpoint metadata rows: `audit_lock_checkpoints` (append-only, mutation blocked)
- Chain rows: `jira_lock_events` (append-only, mutation blocked)

No external/public anchoring is required in this milestone. Internal anchoring is cryptographically bound and verifiable.

## Key Rotation

Checkpoint signing supports key identifiers and rotation.

- Active key listing endpoint exists
- Rotation endpoint exists and activates a new key id
- Checkpoints carry `signing_key_id`
- Verification resolves by key id and validates signature against payload

Operational requirement: maintain a key rotation runbook (frequency, rollback, revoked key handling, and audit trail).

## Fail-Closed Behavior

Override operations now enforce hard validation at API boundaries.

- Required idempotency key (`Idempotency-Key`)
- Required TTL for override/unlock operations
- Maximum TTL enforcement
- Required non-trivial justification
- Admin role enforcement for override operations
- Server-derived expiry (`expires_at` computed server-side)

Invalid requests are denied (`400`/`403`) before ledger mutation.

## Auditor Trust Hook (CLI)

Use these commands for customer/auditor verification:

```bash
releasegate verify lock-ledger --tenant <TENANT> --chain <CHAIN_ID>
releasegate verify checkpoints --tenant <TENANT> --from <YYYY-MM-DD> --to <YYYY-MM-DD>
```

Optional filters:

```bash
releasegate verify lock-ledger --tenant <TENANT> --chain <CHAIN_ID> --from-seq 1 --to-seq 500 --format json
releasegate verify checkpoints --tenant <TENANT> --from 2026-02-01 --to 2026-02-29 --chain <CHAIN_ID> --cadence daily --format json
```

Expected trust properties:

- lock-ledger verify returns chain integrity status
- checkpoints verify returns per-checkpoint signature and replay integrity status

If either command reports invalid output, treat it as a governance integrity incident.
