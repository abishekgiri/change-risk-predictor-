# DSSE + in-toto Interop

ReleaseGate can emit a DSSE envelope containing an in-toto Statement whose `predicate` is the native ReleaseGate release attestation JSON.

This is **additive** interoperability: it does not change core signing, transparency, or Merkle behavior.

## What Gets Emitted

### DSSE Envelope (JSON)

- `payloadType`: `application/vnd.in-toto+json`
- `payload`: base64-encoded canonical JSON bytes of the in-toto Statement
- `signatures[0]`:
  - `keyid`: ReleaseGate attestation signing key id
  - `sig`: base64-encoded raw Ed25519 signature over the decoded `payload` bytes

### in-toto Statement (payload JSON)

- `_type`: `https://in-toto.io/Statement/v1`
- `predicateType`: `https://releasegate.dev/attestation/v1`
- `predicate`: the native ReleaseGate attestation JSON
- `subject[0]`:
  - `name`: `<repo>@<commit_sha>`
  - `digest.sha256`: derived from `predicate.signature.signed_payload_hash`

## Generate DSSE

```bash
releasegate analyze-pr \
  --repo ORG/REPO \
  --pr 123 \
  --tenant ORG \
  --emit-dsse releasegate.dsse.json
```

## Verify DSSE Offline

You need the trusted public key material (single PEM, or a key-id map).

```bash
releasegate verify-dsse \
  --dsse releasegate.dsse.json \
  --key-file attestation/keys/public.pem
```

Exit codes:

- `0`: verified
- `2`: signature invalid or key id unknown
- `3`: invalid file/envelope format

## Public Key Distribution

ReleaseGate exposes public keys via:

- `GET /keys`
- `GET /.well-known/releasegate-keys.json` and `GET /.well-known/releasegate-keys.sig` (root-signed manifest)

For offline-only demos, `attestation/keys/public.pem` can be used as the pinned key.

## Attestation Identity

`attestation_id` is derived from `predicate.signature.signed_payload_hash`:

- `signed_payload_hash`: `sha256:<hex>`
- `attestation_id`: `<hex>` (64 lowercase hex chars)
