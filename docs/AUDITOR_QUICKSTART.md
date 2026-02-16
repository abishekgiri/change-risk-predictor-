# Auditor Quickstart (5 Steps)

## 1) Obtain Artifacts

Collect:

- `attestation.json`
- `proofpack.zip`
- trusted public key map
- (optional) published daily root file under `roots/YYYY-MM-DD.json`

## 2) Verify Attestation Signature

```bash
python -m releasegate.cli verify-attestation attestation.json --format json --key-file keys.json
```

Confirm `valid_signature=true` and `trusted_issuer=true`.

## 3) Verify Proof Pack

```bash
python -m releasegate.cli verify-pack proofpack.zip --format json --key-file keys.json
```

Confirm all checks pass:

- file contract + manifest
- attestation signature/hash
- inclusion proof (if embedded)
- timestamp token (if embedded)

## 4) Validate Transparency Inclusion

CLI path:

```bash
python -m releasegate.cli verify-inclusion --attestation-id <attestation_id> --tenant <tenant> --format json
```

API path (equivalent source data):

- `GET /transparency/proof/{attestation_id}`
- `GET /transparency/root/{date_utc}`

Verify inclusion proof with SDK helper (`verify_inclusion_proof`).

## 5) Validate Published Root

For daily published roots in `roots/`:

- verify root signature using trusted root public key
- confirm root hash/date match transparency proof context
