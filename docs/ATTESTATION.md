# Attestation Contract

This document defines the release attestation contract and canonical signing behavior.

## Contract Source of Truth

- Schema file: `releasegate/attestation/schema/release-attestation.v1.json`
- Runtime model: `releasegate/attestation/types.py`
- Canonicalization: `releasegate/attestation/canonicalize.py`

## Canonicalization Rules

- UTF-8 encoding.
- Lexicographically sorted keys.
- No whitespace variance (`separators=(",", ":")`).
- Contract-aware top-level validation before canonicalization.
- Constants enforced: `schema_version`, `attestation_type`.
- `issued_at` must be UTC ISO8601 with trailing `Z`.
- Non-finite floats are rejected.
- Floats are restricted to approved contract paths (`decision.risk_score` only).

## Signed Payload

The signature is computed over the canonical bytes of the payload **without** the `signature` object.

Primary implementation paths:

- Build/sign: `releasegate/attestation/service.py`
- Verify: `releasegate/attestation/verify.py`

## Hash Contract

- `signed_payload_hash = sha256(canonical_payload_without_signature_bytes)`
- `attestation_id` is derived from this hash in audit storage.

## Compatibility Policy

- `schema_version = "1.0.0"` is the current production contract.
- `policy_schema_version` is included in every attestation to pin policy-DSL compatibility.
- Additive optional fields may be introduced without changing major version.
- Breaking semantic or structural changes require a new schema version.
- Canonicalization behavior for anchored versions is immutable.
