# Security Posture

ReleaseGate is built as Jira-native governance infrastructure. This document describes current security guarantees and operating assumptions.

## Data Handling

- No source code is stored.
- No raw diffs or patch content are stored.
- No repository cloning is required for Jira workflow enforcement.
- Stored data is metadata and governance artifacts only:
  - Decision records and decision snapshots
  - Policy snapshots and policy bundle hashes
  - Override ledger entries
  - Checkpoint/proof-pack artifacts
  - Minimal PR metadata (repo, PR number, change counters)
  - Security/audit events

## Authentication And Authorization

- API auth methods:
  - JWT bearer tokens (`Authorization: Bearer ...`)
  - Tenant-scoped API keys (`X-API-Key`)
  - HMAC webhook signatures (`X-Signature`, `X-Key-Id`, `X-Timestamp`, `X-Nonce`) for webhook endpoints
- Auth resolution and precedence:
  - Webhook routes are signature-only (JWT/API keys are rejected)
  - Non-webhook routes accept JWT or API key
  - Mixed auth methods in one request are rejected and logged
- Every authenticated request resolves:
  - `tenant_id`
  - `principal_id`
  - `auth_method`
  - `roles[]`
  - `scopes[]`
- RBAC roles:
  - `admin`
  - `operator`
  - `auditor`
  - `read_only`
- Sensitive action enforcement:
  - Proof pack export
  - Override creation
  - Policy publish
  - Checkpoint signing key rotation/listing

## API Keys

- API keys are tenant-scoped and scope-scoped.
- Raw keys are shown once at creation.
- Only key hashes are stored at rest (`PBKDF2-HMAC-SHA256`, per-key salt, high iteration count).
- Revocation is supported.
- Rotation is supported (new key issuance + old key revocation).

## Attestation Key Lifecycle

- Key environments are separated by deployment tier:
  - `RELEASEGATE_SIGNING_KEY` / `RELEASEGATE_ATTESTATION_KEY_ID` for attestation signing.
  - `RELEASEGATE_ROOT_SIGNING_KEY` / `RELEASEGATE_ROOT_KEY_ID` for key-manifest and daily-root signing.
  - Distinct values must be used for dev, staging, and prod.
- Rotation model:
  - Introduce a new `key_id`, publish it in `/keys` and the signed manifest.
  - Keep old public keys available for verification until retention windows expire.
  - Revoke compromised keys by setting status `REVOKED` in the signed key manifest.
- Tenant signing-key lifecycle:
  - One `ACTIVE` signing key per tenant.
  - Previous keys move to `VERIFY_ONLY` so older proofs remain verifiable after rotation.
  - `REVOKED` keys are excluded from normal verification key pools.
  - Optional compatibility mode (`RELEASEGATE_ALLOW_REVOKED_SIGNING_KEY_VERIFY=true`) verifies revoked signatures but flags them in verifier output.
- Revocation list artifact:
  - Source of truth: `/.well-known/releasegate-keys.json` (signed by `/.well-known/releasegate-keys.sig`).
  - Revoked keys remain verifiable cryptographically, but are marked untrusted by verifier policy.

## KMS Custody (Phase 7)

- Tenant and checkpoint signing keys are stored with envelope encryption:
  - Private material ciphertext
  - KMS-encrypted data key
  - `kms_key_id`
- `RELEASEGATE_STRICT_KMS=true` enforces boot-time guardrails:
  - service refuses to start unless `RELEASEGATE_KMS_MODE` is a cloud mode (`aws|gcp|azure`)
  - local/mock modes are rejected when strict mode is enabled
- Current implementation status:
  - `local|mock` KMS adapter implemented for development/testing
  - `aws` KMS adapter implemented (`GenerateDataKey`, `Decrypt`, and optional `Sign`)
  - `gcp|azure` adapters are still pending
- Legacy encrypted records can still be read for migration compatibility unless strict mode is enabled.
- Key material access is audit logged (`decrypt`/`sign`) in append-only `key_access_log`.
- AWS KMS runtime configuration:
  - `RELEASEGATE_KMS_MODE=aws`
  - `RELEASEGATE_KMS_KEY_ID=<aws-kms-key-arn-or-id>`
  - optional tuning:
    - `RELEASEGATE_AWS_KMS_REGION`
    - `RELEASEGATE_AWS_KMS_MAX_ATTEMPTS`
    - `RELEASEGATE_AWS_KMS_CONNECT_TIMEOUT_SECONDS`
    - `RELEASEGATE_AWS_KMS_READ_TIMEOUT_SECONDS`
  - optional KMS signing key map:
    - `RELEASEGATE_AWS_KMS_SIGNING_KEYS` (JSON object of `{logical_key_id: kms_key_id}`)
    - `RELEASEGATE_AWS_KMS_SIGNING_ALGORITHM` (default `EDDSA`)
- Live AWS contract test:
  - opt-in with `RELEASEGATE_RUN_AWS_KMS_CONTRACT_TESTS=1`
  - provide `RELEASEGATE_AWS_KMS_CONTRACT_KEY_ID` (or reuse `RELEASEGATE_KMS_KEY_ID`)

## Request Signatures (Webhook Security)

- HMAC signature check for webhook endpoints using key lookup by `X-Key-Id`.
- Tenant and integration are resolved from trusted key storage, not from user-supplied tenant fields.
- Timestamp and nonce are required.
- Maximum clock skew is enforced (default 5 minutes).
- Nonce replay is rejected using persisted nonce records scoped by `(tenant_id, integration_id, nonce)`.
- Signature canonical payload includes timestamp, nonce, HTTP method, request path, and raw body.

## Rate Limiting And Abuse Controls

- Per-IP and per-tenant rate limits are enforced.
- Webhook transition checks also enforce per-issue burst limits to prevent transition spam loops.
- Webhook request flow:
  - per-IP pre-limit is applied before signature verification
  - per-tenant limit is applied after key lookup and before nonce writes
- Default limits are profile-based (`default`, `heavy`, `webhook`) and configurable with `RELEASEGATE_RATE_LIMIT_*` environment overrides.
- Higher-sensitivity endpoints use stricter limits:
  - replay
  - simulation
  - export/proof-pack
- Hard request bounds:
  - request body hard cap (not only `Content-Length`)
  - capped `limit` values on heavy endpoints
  - deterministic 429 responses with `Retry-After`

## Retention

- Implemented today:
  - Webhook nonces are short-lived and cleaned by TTL on use.
- Planned (not fully implemented in code yet):
  - Tenant-configurable retention windows for decisions, policy snapshots, security events, and proof artifacts.
  - Automated deletion/archival jobs for expired records.

## Threat Model Summary

- Spoofed webhook requests:
  - Mitigated by HMAC signature + timestamp + nonce.
- Replay attacks:
  - Mitigated by nonce store and timestamp skew validation.
- Cross-tenant data leakage:
  - Mitigated by tenant-scoped composite primary keys and tenant authorization checks.
- Tampering attempts:
  - Mitigated by append-only ledger behavior, hash-chained override records, and checkpoint verification.
- Credential leakage:
  - Mitigated by slow-KDF API-key hash storage, JWT claim validation, and key rotation.

## Integrity Properties

- Hashed:
  - Decision canonical JSON hash
  - Override event hash and chain root
  - API key hash
  - Checkpoint signing key hash
- Signed:
  - Checkpoint payloads (HMAC)
  - Webhook request payloads (HMAC)
- Note:
  - Checkpoint verification currently uses HMAC-SHA256 shared secrets; offline verification therefore requires access to signing-secret material. Public-key verification is planned.
- Append-only:
  - Override ledger
  - Security audit events
- Verifiable/replayable:
  - Decision replay from stored snapshot + policy bindings
  - Override chain verification
  - Checkpoint verification

## Forge Runtime Hardening

- Transition evaluations emit structured JSON logs with `decision_id`, `tenant_id`, `request_id`, `policy_bundle_hash`, `result`, and `reason_code`.
- Dependency timeouts are deterministic:
  - strict mode: `BLOCKED` + `TIMEOUT_DEPENDENCY`
  - permissive mode: `SKIPPED` + `SKIPPED_TIMEOUT`
- Deploy-time policy bundle validation is available via:
  - `python -m releasegate.cli validate-policy-bundle`
