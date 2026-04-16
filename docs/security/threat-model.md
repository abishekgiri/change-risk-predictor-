# Threat Model (Attestations + DSSE)

This document describes what ReleaseGate’s attestation/DSSE layer is designed to protect against, what it does not protect against, and the operational assumptions required for meaningful verification.

## Assets

- Release attestation payload integrity (`signed_payload_hash`).
- DSSE envelope integrity (signed in-toto Statement payload).
- Key trust and key selection (key id pinning / rotation).
- Transparency inclusion proofs and published roots (when enabled).

## Trust Assumptions

- Verifiers use a trusted key source:
  - pinned public key(s), or
  - a root-signed key manifest (`/.well-known/...`) with a pinned root public key.
- Build environments are not compromised (a compromised runner can produce “valid” signatures).
- The repository and CI configuration are the intended authority for a given attestation.

## Threats Mitigated

### Payload tampering

- Any modification to the signed payload bytes changes the hash and invalidates signatures.
- DSSE verification fails on 1-byte payload changes.

### Key substitution (CI safety)

- `verify-dsse --require-keyid <id>` (or `--require-signers ...`) prevents a valid signature from an unexpected key from being accepted in pipelines.
- Key maps must contain the expected key id(s); unknown keys fail closed.

### Replay / wrong-context use (optional checks)

Verifiers can enforce that an attestation applies to the expected context:

- `--require-repo <owner/repo>`
- `--require-commit <sha>`
- `--max-age 7d`

This reduces the risk of replaying a valid old attestation for a different repo/commit.

### Auditability (artifact integrity)

- CI can emit a `releasegate.artifacts.sha256` manifest to make artifact integrity checks trivial.
- Optional JSONL index logs can bind a DSSE artifact hash to an append-only record for internal auditing.

## Threats Not Mitigated

- Compromised CI runners, compromised repository secrets, or malicious code in the repo can produce valid signatures.
- If a verifier fetches keys from an untrusted network endpoint without a pinned trust root, key spoofing is possible.
- Local JSONL “index logs” are not a public transparency log; they do not prevent deletion or rewriting by an attacker with filesystem access.

## Trust Fabric Threats

### Trust score manipulation

- **Threat**: An operator degrades trust components (e.g., disables signal freshness) to lower the bar for non-compliant releases.
- **Mitigation**: Trust score is computed server-side from auditable state. Component weights are fixed. Historical trust scores are queryable through the evidence graph for regression detection.

### Checkpoint staleness

- **Threat**: Checkpoint signing stops silently, and the system operates without fresh cryptographic proof.
- **Mitigation**: The trust score includes a 20-point "Checkpoint Fresh" component with a 36-hour threshold. Stale checkpoints are visible in the dashboard and degrade the trust score automatically.

### Evidence graph query evasion

- **Threat**: Decisions are structured to avoid evidence graph filters (e.g., missing actor fields).
- **Mitigation**: All decisions are written through a single code path that enforces required fields. The evidence graph exposes integrity hashes for every result, enabling cross-verification against the raw ledger.

### Signal replay

- **Threat**: An attacker replays old signal data to influence a decision with stale context.
- **Mitigation**: Zero-trust signal freshness enforces `max_age_seconds`, `require_computed_at`, and `fail_on_stale` to reject signals beyond the configured window.

### Append-only trigger bypass

- **Threat**: A database administrator disables triggers to mutate audit records.
- **Mitigation**: Trigger protection is verified at startup. Merkle tree roots provide an independent integrity check — any mutation breaks the inclusion proofs. External RFC 3161 anchors provide proof-of-existence that survives database compromise.

## Operational Guidance

- Prefer root-signed key manifests for key distribution; pin the root key in verifier configuration.
- Rotate attestation signing keys regularly; keep old keys available for verification during a grace period.
- Use `--require-keyid`/`--require-signers` in CI to prevent silent key drift.
- Treat `--keys-url` as convenience; for strong guarantees, verify a signed manifest.
- Monitor the trust score dashboard — any score below 80 should trigger investigation.
- Enable `fail_on_stale` in signal freshness config for production environments.
- Anchor checkpoints to at least one external timestamp authority for independent verification.

