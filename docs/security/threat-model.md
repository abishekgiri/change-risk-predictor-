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

## Operational Guidance

- Prefer root-signed key manifests for key distribution; pin the root key in verifier configuration.
- Rotate attestation signing keys regularly; keep old keys available for verification during a grace period.
- Use `--require-keyid`/`--require-signers` in CI to prevent silent key drift.
- Treat `--keys-url` as convenience; for strong guarantees, verify a signed manifest.

