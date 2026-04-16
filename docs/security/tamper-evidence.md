# Tamper-Evidence Architecture

This document explains what is immutable in ReleaseGate, how tampering is detected, and how an auditor can independently verify any integrity claim.

## What Is Immutable

### Append-Only Database Tables

The following tables are protected by database-level triggers that raise an exception and abort the transaction if any UPDATE or DELETE is attempted:

| Table | Contains |
| --- | --- |
| `audit_decisions` | Every policy decision with its input, verdict, and four integrity hashes |
| `audit_overrides` | Every manual exception/override with actor, justification, TTL |
| `audit_attestations` | Signed release attestations with DSSE envelopes |
| `audit_transparency_log` | Transparency log entries for Merkle tree inclusion |
| `audit_transparency_roots` | Published Merkle root hashes |
| `jira_lock_events` | Jira workflow lock/unlock event ledger |
| `audit_decision_refs` | Cross-references between decisions and related artifacts |
| `policy_resolved_snapshots` | Policy snapshots bound to decisions at evaluation time |
| `policy_decision_records` | Policy-scoped decision records for audit trail |
| `audit_lock_checkpoints` | Signed checkpoint records for the lock event ledger |

These triggers work on both SQLite (test/dev) and PostgreSQL (production). Any mutation attempt raises an exception, which is logged as a security event.

### Per-Decision Integrity Hashes

Every record in `audit_decisions` carries four hashes computed at decision time:

| Hash | What it covers |
| --- | --- |
| `decision_hash` | The full decision output (verdict, reason code, all outputs) |
| `input_hash` | The complete input context (risk data, signals, PR metadata) |
| `policy_hash` | The policy snapshot active at evaluation time |
| `replay_hash` | A deterministic replay of the evaluation — must match `decision_hash` |

A mismatch between any of these hashes is proof of tampering.

## What Is Checkpointed

### Daily Signed Checkpoints

A checkpoint is published for each UTC day that has activity. Each checkpoint contains:

- `root_hash`: The Merkle root of all transparency log entries for the period
- `event_count`: Number of events included
- `prev_checkpoint_hash`: Hash of the prior checkpoint, forming a hash chain
- `signature`: Ed25519 signature from the tenant signing key or root key

The hash chain means tampering with any past checkpoint invalidates all subsequent checkpoints.

### RFC 3161 External Anchoring

Checkpoint root hashes are submitted to an external timestamp authority (TSA) using RFC 3161. The TSA returns a signed timestamp token that:

1. Proves the checkpoint root hash existed at a specific point in time
2. Is signed by a CA that is independent of ReleaseGate
3. Remains verifiable even if the ReleaseGate database is deleted or replaced

This makes it impossible to silently rewrite history — any rewritten root would fail to match the externally anchored hash.

### Merkle Tree Inclusion Proofs

Every transparency log entry has an inclusion proof: a set of sibling hashes that, when combined with the leaf hash, reproduce the published Merkle root. An auditor can verify any individual record without downloading the full log.

## How Tampering Is Detected

### Scenario 1: Database record mutation

An attacker with direct database access changes a decision verdict.

**Detection path:**
1. The `decision_hash` stored at write time no longer matches a recomputed hash of the record.
2. The `replay_hash` diverges from the stored `decision_hash` when the decision is replayed.
3. The Merkle inclusion proof for the transparency log entry fails because the leaf hash changed.
4. The checkpoint root hash for the period no longer matches — breaking the hash chain forward.
5. The RFC 3161 token references the original root hash, creating irrefutable proof of the discrepancy.

### Scenario 2: Trigger removal

An attacker disables the append-only triggers, then mutates records.

**Detection path:**
1. Trigger status is checked at application startup and logged.
2. Hash chain verification (`GET /audit/checkpoints/override/verify`) detects the break.
3. The Merkle root for the period diverges from the externally anchored root.

### Scenario 3: Checkpoint replacement

An attacker replaces a checkpoint with a freshly computed one covering altered records.

**Detection path:**
1. The RFC 3161 token for the original root hash references a different timestamp and root.
2. Any verifier with the original TSA token can prove the new checkpoint was created after the fact.

### Scenario 4: Stale signal injection

An attacker replays an old risk signal to make a blocked deployment appear compliant.

**Detection path:**
1. Signal freshness enforcement rejects signals older than `max_age_seconds` at evaluation time.
2. The `signal_hash` covers the signal content — a different signal produces a different hash.
3. The `input_hash` in the decision record covers all inputs including the signal — any change is detectable.

## How to Verify a Claim

### Verify a single decision

```bash
# Pull the proof pack for a decision
GET /audit/proof-pack/{decision_id}

# Or use the CLI offline
python -m releasegate.cli verify-pack \
  --pack decision-proof.zip \
  --format json \
  --key-file public-keys.json
```

The verifier checks:
1. `decision_hash` matches a recomputed hash of the decision payload
2. `replay_hash` matches `decision_hash`
3. Attestation signature is valid
4. Merkle inclusion proof is valid
5. RFC 3161 token is valid (when TSA CA bundle is provided)

### Verify the full ledger

```bash
# Verify hash chain for override ledger
GET /audit/checkpoints/override/verify?tenant_id=<tenant>&repo=<repo>

# Verify daily checkpoint
GET /anchors/checkpoints/daily/{date_utc}/verify?tenant_id=<tenant>
```

### Verify a Merkle inclusion proof offline

```bash
python -m releasegate.cli verify-inclusion \
  --attestation-id <id> \
  --tenant <tenant> \
  --format json
```

Steps the verifier applies:
1. Compute `leaf_hash` from the leaf payload using the `leaf_version=1` contract
2. Apply proof steps (left/right siblings) using `sha256(left || right)`
3. Compare final computed hash to the published `root_hash`

See [transparency_merkle.md](../transparency_merkle.md) for the full leaf contract.

### Check trust score

The trust score at `GET /audit/trust-status` aggregates all of the above into a 0–100 signal:

- **100**: All six trust components pass — system integrity is fully provable
- **≥80**: Strong — suitable for audit review
- **50–79**: Moderate — one or two components need attention
- **<50**: Weak — critical gaps require investigation before audit

A score below 80 should trigger investigation of which components are failing.
