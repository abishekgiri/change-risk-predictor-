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

## External Root Publication

Daily signed roots are exported to repository path:

- `roots/YYYY-MM-DD.json`

via workflow:

- `.github/workflows/publish-roots.yml`

Publication behavior:

1. Try yesterday (UTC).
2. If no root exists for yesterday, try today (UTC).
3. If neither day has entries, workflow exits successfully without commit.
4. Root payload is signed with the root Ed25519 key (`RELEASEGATE_ROOT_SIGNING_KEY`).

## Inclusion Proof Verification
To verify proof offline:

1. Compute `leaf_hash` from the leaf payload using `leaf_version=1` fields.
2. Apply proof steps in order (`left`/`right`) using `sha256(left || right)`.
3. Compare final computed hash with `root_hash`.
4. Verification succeeds only if hashes match exactly.

## Public Root Verification Procedure

1. Load `roots/<date>.json`.
2. Split payload and `signature`.
3. Canonicalize payload bytes with attestation canonical JSON rules.
4. Verify `signature.sig` using trusted root public key for `signature.root_key_id`.
5. Compare included `root_hash` with root returned by `/transparency/root/<date>` when online verification is desired.
