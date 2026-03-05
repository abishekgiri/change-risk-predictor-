# Proof Bundle Verification Guide

## Purpose

This guide describes how an external auditor can independently verify a ReleaseGate decision proof bundle.

## Proof Bundle Contents

A proof bundle should contain (names may vary by export mode):

- `decision.json`
- `policy_snapshot.json`
- `evidence.json`
- `signature.dsse` (or equivalent signature envelope)
- `anchor_receipt.json`

These artifacts prove:

- decision integrity (what was decided)
- policy integrity (which policy snapshot was used)
- evidence integrity (what inputs were evaluated)
- timeline integrity (when it was anchored)

## Prerequisites

- Access to the exported proof bundle for a specific `decision_id`.
- SHA-256 tool (`sha256sum` or `shasum -a 256`).
- Signature verification tool used by your environment.
- Access to anchor verification metadata from `anchor_receipt.json`.

## Step 1: Validate Decision Hash

Compute the hash of `decision.json`:

```bash
shasum -a 256 decision.json
```

Compare the computed digest with the expected hash in the bundle metadata (`decision_hash` / bound hash fields). They must match exactly.

## Step 2: Verify Signature Envelope

Validate `signature.dsse` (or equivalent envelope) against the expected public key:

- signature must be valid
- payload digest in signature must match decision/policy binding hashes

If signature verification fails, treat the bundle as untrusted.

## Step 3: Verify Policy Snapshot Binding

Compute the hash of `policy_snapshot.json` and verify it matches the policy hash referenced by the decision artifact.

Expected checks:

- decision references a specific policy snapshot hash
- snapshot hash matches computed hash
- no mismatch between decision and snapshot metadata

## Step 4: Verify Evidence Integrity

Validate that evidence payload hashes (if present) match raw evidence files.

At minimum:

- evidence identifiers in `decision.json` exist in `evidence.json`
- optional per-evidence hashes (if exported) are consistent

## Step 5: Validate Anchoring Receipt

Use `anchor_receipt.json` to verify inclusion in the configured transparency/anchor system.

Required validations:

- checkpoint/root hash in receipt matches the bundle hash chain reference
- anchor timestamp is consistent with decision creation timeline
- anchor reference can be resolved or validated against recorded metadata

## Expected Auditor Outcome

A bundle is valid when all checks pass:

- hash integrity: pass
- signature verification: pass
- policy snapshot binding: pass
- anchor verification: pass

If any check fails, the decision artifact should be flagged for incident review.
