# External Anchoring Readiness (55-Step Wave Plan)

This file maps the 55-step execution plan into four ordered waves.
Do not start a later wave until all `MISSING`/`PARTIAL` items in the prior wave are closed.

## Status Summary

- `DONE`: 55
- `PARTIAL`: 0
- `MISSING`: 0

## Wave 1 — Deterministic Attestation Core

| # | Requirement | Status | Primary Files | Close Action |
|---|---|---|---|---|
| 1 | Freeze attestation schema v1 in repo | DONE | `releasegate/attestation/schema/release-attestation.v1.json` | Keep immutable; only additive optional fields. |
| 2 | Single source-of-truth schema ownership documented | DONE | `docs/decision-model.md`, `docs/security.md` | Implemented and validated. |
| 3 | Core v1 field contract exactly matches governance spec | DONE | `releasegate/attestation/types.py`, `releasegate/attestation/schema/release-attestation.v1.json` | Implemented and validated. |
| 4 | Remove optional randomness from signed payload | DONE | `releasegate/attestation/service.py` | Keep timestamp sourced from deterministic bundle input. |
| 5 | `canonicalize_attestation(attestation)` exists | DONE | `releasegate/attestation/canonicalize.py` | Keep as canonical entrypoint. |
| 6 | Canonicalization uses UTF-8 + sorted keys + no whitespace drift | DONE | `releasegate/attestation/canonicalize.py` | No change. |
| 7 | Contract-aware top-level validation before canonicalization | DONE | `releasegate/attestation/canonicalize.py` | No change. |
| 8 | Top-level contract constants enforced (`schema_version`, `attestation_type`) | DONE | `releasegate/attestation/canonicalize.py` | No change. |
| 9 | Timestamp format determinism rule locked (ISO8601 Z policy) | DONE | `releasegate/attestation/service.py` | Implemented and validated. |
| 10 | No-floats rule enforced in canonical payload | DONE | `releasegate/attestation/types.py`, `releasegate/attestation/canonicalize.py` | Implemented and validated. |
| 11 | Attestation hash root (`sha256(canonical_bytes)`) computed/exposed | DONE | `releasegate/attestation/service.py`, `releasegate/attestation/verify.py` | Continue exposing as `signed_payload_hash`. |
| 12 | Tamper test: value change => hash change | DONE | `tests/attestation/test_attestation_determinism.py` | No change. |
| 13 | Determinism test: key reorder => hash unchanged | DONE | `tests/attestation/test_attestation_determinism.py` | No change. |
| 14 | Golden determinism test across 100 runs | DONE | `tests/attestation/test_attestation_determinism.py` | No change. |

## Wave 2 — Cryptographic Integrity

| # | Requirement | Status | Primary Files | Close Action |
|---|---|---|---|---|
| 15 | Ed25519 signing implemented | DONE | `releasegate/attestation/crypto.py` | No change. |
| 16 | Signer fails closed on missing key | DONE | `releasegate/attestation/crypto.py` | No change. |
| 17 | `kid`/key id attached to attestation issuer | DONE | `releasegate/attestation/service.py` | No change. |
| 18 | Signature verify function implemented | DONE | `releasegate/attestation/verify.py` | No change. |
| 19 | CLI verify command fails non-zero on invalid payload/signature | DONE | `releasegate/cli.py` | No change. |
| 20 | API verification endpoint exists | DONE | `releasegate/server.py` | No change. |
| 21 | Tamper verification tests exist | DONE | `tests/test_attestation.py`, `tests/test_dsse.py` | No change. |
| 22 | Unknown key id test exists | DONE | `tests/test_dsse.py`, `tests/attestation/test_key_manifest.py` | No change. |
| 23 | Root-signed key manifest implemented | DONE | `releasegate/attestation/key_manifest.py`, `releasegate/server.py` | No change. |
| 24 | Revocation semantics reflected in verification behavior | DONE | `releasegate/attestation/sdk.py`, `tests/attestation/test_key_manifest.py` | Implemented and validated. |
| 25 | Dev/stage/prod key separation policy | DONE | `docs/security.md` | Implemented and validated. |
| 26 | Rotation policy documented and operationalized | DONE | `docs/security.md`, `releasegate/server.py` | Implemented and validated. |
| 27 | Revocation list artifact/process (file or endpoint contract) | DONE | `docs/security.md` | Implemented and validated. |

## Wave 3 — Evidence and Ledger

| # | Requirement | Status | Primary Files | Close Action |
|---|---|---|---|---|
| 28 | Proof-pack generation command exists | DONE | `releasegate/cli.py` | No change. |
| 29 | Proof-pack verification command exists | DONE | `releasegate/cli.py`, `releasegate/audit/proof_pack_verify.py` | No change. |
| 30 | Proof-pack contract frozen to strict artifact set | DONE | `docs/contracts/proof_pack_v1.md`, `releasegate/cli.py` | Implemented and validated. |
| 31 | Deterministic proof-pack file ordering | DONE | `releasegate/cli.py` | Keep ordered writes stable. |
| 32 | Stable zip metadata for byte-identical archives | DONE | `releasegate/audit/proofpack_v1.py` | Fixed zip timestamps/attrs and stored mode for deterministic bytes. |
| 33 | Proof-pack hash recorded (`export_checksum`) | DONE | `releasegate/cli.py` | No change. |
| 34 | Reproducibility test: same inputs => same proof-pack bytes | DONE | `tests/audit/test_proofpack_v1.py` | Byte-for-byte deterministic regression tests are in place. |
| 35 | Include `attestation.json` + signature artifact in proof-pack | DONE | `releasegate/audit/proofpack_v1.py`, `releasegate/cli.py` | Deterministic proofpack includes attestation and detached signature text. |
| 36 | Include TSA timestamp token when enabled | DONE | `releasegate/cli.py` | Implemented and validated. |
| 37 | Append-only attestation/transparency persistence | DONE | `releasegate/audit/attestations.py`, `releasegate/audit/transparency.py` | No change. |
| 38 | Duplicate attestation rejection by hash/id | DONE | `releasegate/audit/attestations.py` | No change. |
| 39 | Immutability guarantees for attestation records | DONE | `releasegate/audit/attestations.py`, `releasegate/storage/schema.py` | Implemented and validated. |
| 40 | API: `GET /attestations/{hash}` | DONE | `releasegate/server.py` | Implemented and validated. |
| 41 | API: query attestations by repo/since | DONE | `releasegate/audit/transparency.py`, `releasegate/server.py` | Implemented and validated. |

## Wave 4 — Controlled External Anchoring

| # | Requirement | Status | Primary Files | Close Action |
|---|---|---|---|---|
| 42 | Anchor provider interface (`anchor`, `verify`) | DONE | `releasegate/` | Implemented and validated. |
| 43 | Local transparency-log provider implementation | DONE | `releasegate/audit/transparency.py` | Implemented and validated. |
| 44 | Config-based provider selection | DONE | `releasegate/config.py`, `releasegate/cli.py` | Implemented and validated. |
| 45 | Attestation append into transparency log | DONE | `releasegate/audit/attestations.py`, `releasegate/audit/transparency.py` | No change. |
| 46 | Deterministic daily Merkle root computation | DONE | `releasegate/attestation/merkle.py`, `releasegate/audit/transparency.py` | No change. |
| 47 | Inclusion proof endpoint | DONE | `releasegate/server.py`, `releasegate/audit/transparency.py` | No change. |
| 48 | Offline inclusion verifier helper | DONE | `releasegate/attestation/sdk.py` | No change. |
| 49 | CLI inclusion verification command | DONE | `releasegate/cli.py` | Implemented and validated. |
| 50 | Daily signed root publishing workflow | DONE | `.github/workflows/publish-roots.yml` | No change. |
| 51 | Root export contains date/count/hash/signature | DONE | `releasegate/audit/root_export.py` | No change. |
| 52 | Public root publication docs and verification procedure | DONE | `docs/transparency_merkle.md`, `README.md` | Implemented and validated. |
| 53 | Optional anchoring toggle (`enabled/disabled`) | DONE | `releasegate/config.py` | Implemented and validated. |
| 54 | RFC3161 timestamping adapter + verification | DONE | `releasegate/` | Implemented and validated. |
| 55 | Auditor-ready docs set (`ATTESTATION`, `VERIFICATION`, quickstart) | DONE | `docs/ATTESTATION.md`, `docs/VERIFICATION.md`, `docs/AUDITOR_QUICKSTART.md` | Keep updated with schema/runtime changes. |

## Immediate Closures Applied

- All 55 wave requirements are now implemented and validated in code/docs.
- Remaining work is operational cadence (running workflows/rotations), not missing implementation.
