# Transparency Merkle Rules

This document defines the immutable cryptographic contract for transparency Merkle anchoring.

## Leaf Contract (`leaf_version=1`)
Each transparency leaf hash is:

`sha256(canonical_json({...}))`

Canonical leaf payload fields:

- `leaf_version`
- `attestation_id`
- `payload_hash`
- `issued_at`
- `repo`
- `commit_sha`
- `pr_number`

## Deterministic Ordering
Leaves for a UTC day are ordered by:

1. `issued_at` ascending
2. `attestation_id` ascending (tie-breaker)

## Tree Rules
- Hash algorithm: `SHA-256`
- Parent hash: `sha256(left || right)`
- Odd leaf rule: duplicate last leaf
- Tree rule identifier: `sha256_concat_duplicate_last`

## Root and Proof APIs
- `GET /transparency/root/{date_utc}`
- `GET /transparency/proof/{attestation_id}`

Both responses are cacheable and include ETag headers.

## Inclusion Proof Verification
To verify proof offline:

1. Compute `leaf_hash` from the leaf payload using `leaf_version=1` fields.
2. Apply proof steps in order (`left`/`right`) using `sha256(left || right)`.
3. Compare final computed hash with `root_hash`.
4. Verification succeeds only if hashes match exactly.
