# DSSE + in-toto Interop

ReleaseGate can emit a DSSE envelope containing an in-toto Statement whose `predicate` is the native ReleaseGate release attestation JSON.

This is **additive** interoperability: it does not change core signing, transparency, or Merkle behavior.

## What Gets Emitted

### DSSE Envelope (JSON)

- `payloadType`: `application/vnd.in-toto+json`
- `payload`: base64-encoded canonical JSON bytes of the in-toto Statement (JCS/RFC8785 subset)
- `signatures[0]` (default `--dsse-signing-mode ed25519`):
  - `keyid`: ReleaseGate attestation signing key id
  - `sig`: base64-encoded raw Ed25519 signature over the decoded `payload` bytes

Optional `--dsse-signing-mode sigstore`:

- `signatures[0].keyid`: `sigstore`
- `signatures[0].sig`: base64 signature produced by Sigstore keyless signing (via `cosign sign-blob`)
- bundle file: `<emit-dsse>.sigstore.bundle.json` (or `--dsse-sigstore-bundle <path>`)

### in-toto Statement (payload JSON)

- `_type`: `https://in-toto.io/Statement/v1`
- `predicateType`: `https://releasegate.dev/attestation/v1`
- `predicate`: the native ReleaseGate attestation JSON
- `subject[0]`:
  - `name`: `git+https://github.com/<repo>@<commit_sha>`
  - `digest.sha256`: derived from `predicate.signature.signed_payload_hash`

## Generate DSSE

```bash
releasegate analyze-pr \
  --repo ORG/REPO \
  --pr 123 \
  --tenant ORG \
  --emit-dsse releasegate.dsse.json
```

Sigstore keyless mode (requires `cosign` installed and OIDC identity available):

```bash
releasegate analyze-pr \
  --repo ORG/REPO \
  --pr 123 \
  --tenant ORG \
  --emit-dsse releasegate.dsse.json \
  --dsse-signing-mode sigstore
```

## Verify DSSE Offline

You need the trusted public key material (single PEM, or a key-id map).

```bash
releasegate verify-dsse \
  --dsse releasegate.dsse.json \
  --key-file attestation/keys/public.pem \
  --require-keyid "<keyid>"
```

Exit codes:

- `0`: verified
- `2`: signature invalid, key id unknown, or key id does not match `--require-keyid`
- `3`: invalid file/envelope format

Sigstore verification (keyless, using the bundle JSON written at signing time):

```bash
releasegate verify-dsse \
  --dsse releasegate.dsse.json \
  --sigstore-bundle releasegate.dsse.json.sigstore.bundle.json \
  --sigstore-identity "https://github.com/ORG/REPO/.github/workflows/<workflow>.yml@refs/..." \
  --sigstore-issuer "https://token.actions.githubusercontent.com"
```

Optional verifier controls:

- `--require-signers <kid1,kid2>`: require multiple valid signatures
- `--require-repo <owner/repo>`: enforce repo binding
- `--require-commit <sha>`: enforce commit binding
- `--max-age 7d`: enforce freshness using `predicate.issued_at`
- `--keys-url <url>`: fetch a key map from an HTTP endpoint (convenience)

## Public Key Distribution

ReleaseGate exposes public keys via:

- `GET /keys`
- `GET /.well-known/releasegate-keys.json` and `GET /.well-known/releasegate-keys.sig` (root-signed manifest)

For offline-only demos, `attestation/keys/public.pem` can be used as the pinned key.

## Attestation Identity

`attestation_id` is derived from `predicate.signature.signed_payload_hash`:

- `signed_payload_hash`: `sha256:<hex>`
- `attestation_id`: `<hex>` (64 lowercase hex chars)

## Compatibility Notes

- `proofpack_v1` does not embed DSSE envelopes by design; it has a fixed file contract.
- DSSE is distributed as a parallel artifact (for example `releasegate.dsse.json`).
- The DSSE + in-toto contract is intended to remain stable across minor versions.

## Optional Index Log

You can bind a DSSE artifact hash to an append-only JSONL log:

```bash
releasegate log-dsse --dsse releasegate.dsse.json --log attestations.log
releasegate verify-log --dsse releasegate.dsse.json --log attestations.log
```
