# `proof_pack_v1` Contract

## Identity
- Artifact id: `proof_pack_v1`
- Deterministic zip builder: `releasegate/audit/proofpack_v1.py`
- CLI export: `python -m releasegate.cli proofpack`
- CLI verify: `python -m releasegate.cli verify-pack`

## Required Files (Exact Order)
The zip archive order is immutable:

1. `attestation.json`
2. `signature.txt`
3. `inputs.json`
4. `decision.json`
5. `manifest.json`

Optional files are appended in this exact order when enabled:

6. `receipt.json`
7. `inclusion_proof.json`
8. `timestamp.json`
9. `rfc3161.tsr`

If a feature is disabled, its optional file is omitted (never empty placeholder files).

## Deterministic Zip Rules
- UTF-8 canonical JSON for all JSON files.
- Lexicographic key order and minified separators.
- Zip mode is `ZIP_STORED`.
- Each entry uses fixed metadata:
  - timestamp: `1980-01-01T00:00:00` (zip epoch)
  - permissions: `0644`
- Proofpack bytes are reproducible for identical logical inputs.

## `manifest.json`
`manifest.json` is canonical JSON with:
- `proofpack_version`: `"v1"`
- `created_by`: engine version string
- `attestation_hash`: sha256 hex of signed payload
- `payload_hash`: signed payload hash (`sha256:<hex>`)
- `files`: ordered list matching zip order (excluding `manifest.json`), each item contains:
  - `path`
  - `sha256`
  - `size_bytes`

## Verification Contract
`verify-pack` must validate in this order:
1. Zip file set and order.
2. `manifest.json` structure and per-file checksums/sizes.
3. Attestation signature and hash binding.
4. `signature.txt` equals detached signature in `attestation.json`.
5. Inclusion proof (when `inclusion_proof.json` exists).
6. RFC3161 timestamp token (when `timestamp.json` + `rfc3161.tsr` exist).

## Compatibility Rules
- `proof_pack_v1` is immutable.
- Additive optional files are allowed only if explicitly listed above.
- Any breaking change requires `proof_pack_v2`.
