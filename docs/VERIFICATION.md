# Verification Guide

This guide covers offline verification for attestations, proofpacks, inclusion proofs, and published transparency roots.

## Verify Attestation Offline

```bash
python -m releasegate.cli verify-attestation /path/to/attestation.json --format json --key-file /path/to/public-keys.json
```

Expected booleans:

- `schema_valid=true`
- `payload_hash_match=true`
- `valid_signature=true`
- `trusted_issuer=true`

## Verify DSSE + in-toto Offline

```bash
releasegate verify-dsse --dsse /path/to/releasegate.dsse.json --format json --key-file /path/to/public-keys.json
```

See `docs/attestations/dsse-intoto.md` for the emitted contract.

## Verify Deterministic Proofpack v1

```bash
python -m releasegate.cli verify-pack /path/to/proofpack.zip --format json --key-file /path/to/public-keys.json
```

Optional RFC3161 validation:

```bash
python -m releasegate.cli verify-pack /path/to/proofpack.zip --format json --tsa-ca-bundle /path/to/tsa-ca.pem
```

Verifier checks:

1. Zip file contract and deterministic order.
2. `manifest.json` hashes/sizes.
3. Attestation signature and payload hash.
4. Detached `signature.txt` consistency.
5. Inclusion proof validity (when embedded).
6. RFC3161 token validity (when embedded and CA bundle supplied).

## Verify Inclusion Proof

From stored attestation id:

```bash
python -m releasegate.cli verify-inclusion --attestation-id <attestation_id> --tenant <tenant> --format json
```

From proof file:

```bash
python -m releasegate.cli verify-inclusion --proof-file inclusion_proof.json --format json
```

## Verify External Root Signature

Published daily roots are signed and exported by `releasegate export-root`.

- Signature helper: `releasegate/audit/root_export.py:verify_external_root_payload`
- Public roots: `roots/YYYY-MM-DD.json`

## Failure Posture

All verification paths are fail-closed:

- Invalid schema/hash/signature/proof -> non-success result.
- CLI exit codes:
  - `0`: verification succeeded
  - `2`: verification failed
  - `3`: invalid/unreadable input artifact
