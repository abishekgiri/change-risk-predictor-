# `checkpoint_v1` Format

## Identity
- Artifact ID: `checkpoint_v1`
- Create endpoint: `POST /audit/checkpoints/override`
- Verify endpoint: `GET /audit/checkpoints/override/verify`
- CLI command: `releasegate checkpoint-override`

## Stored Checkpoint Shape
Top-level object:
- `checkpoint_version`: string, must be `v1`
- `payload`: object
- `signature`: object

Payload fields:
- `repo`: string
- `pr_number`: integer or `null`
- `cadence`: enum (`daily`, `weekly`)
- `period_id`: string (for example `2026-02-12` or `2026-W07`)
- `period_end`: UTC timestamp string
- `root_hash`: hex string
- `event_count`: integer
- `first_event_at`: UTC timestamp string or `null`
- `last_event_at`: UTC timestamp string or `null`
- `generated_at`: UTC timestamp string

Signature fields:
- `algorithm`: string, currently `HMAC-SHA256`
- `value`: hex string

## Verification Response
- `exists`: boolean
- `valid`: boolean
- `repo`: string
- `cadence`: string
- `period_id`: string
- `signature_valid`: boolean
- `signature_error`: string or `null`
- `chain_valid`: boolean
- `root_hash_match`: boolean
- `event_count_match`: boolean
- `checkpoint_root_hash`: string
- `computed_root_hash`: string
- `checkpoint_event_count`: integer
- `computed_event_count`: integer
- `period_end`: UTC timestamp string
- `path`: string
- `chain_reason`: string, optional when chain invalid
- `override_id`: string, optional when chain invalid

## Signing and Storage
- Signing key source: `RELEASEGATE_CHECKPOINT_SIGNING_KEY`.
- Checkpoint store directory: `RELEASEGATE_CHECKPOINT_STORE_DIR` (default `audit_bundles/checkpoints`).

## Stability Rules
- `payload` and `signature` top-level structures are stable in `checkpoint_v1`.
- Verification keys listed above are stable in `checkpoint_v1`.
- Additive fields are allowed.
- Breaking changes require `checkpoint_v2`.
