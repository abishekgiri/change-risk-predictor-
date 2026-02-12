# `proof_pack_v1` Format

## Identity
- Artifact ID: `proof_pack_v1`
- Endpoint: `GET /audit/proof-pack/{decision_id}`
- Formats: `json`, `zip`
- On-wire bundle version: `audit_proof_v1`

## JSON Bundle
Top-level fields:
- `schema_name`: string, `proof_pack`
- `schema_version`: string, `proof_pack_v1`
- `bundle_version`: string, currently `audit_proof_v1`
- `generated_at`: UTC timestamp string
- `tenant_id`: string
- `ids`: object
- `integrity`: object
- `decision_id`: string
- `repo`: string or `null`
- `pr_number`: integer or `null`
- `decision_snapshot`: object
- `policy_snapshot`: array
- `input_snapshot`: object
- `override_snapshot`: object or `null`
- `ledger_segment`: array (minimal override records required for offline chain verification)
- `checkpoint_snapshot`: object or `null`
- `chain_proof`: object or `null`
- `checkpoint_proof`: object or `null`
- `export_checksum`: hex string
- `proof_pack_id`: string

`integrity` fields:
- `canonicalization`: `releasegate-canonical-json-v1`
- `hash_alg`: `sha256`
- `input_hash`
- `policy_hash`
- `decision_hash`
- `replay_hash`
- `ledger.ledger_tip_hash`
- `ledger.ledger_record_id`
- `signatures.checkpoint_signature`
- `signatures.signing_key_id`

Checkpoint signature note:
- `checkpoint_signature` is currently produced with HMAC-SHA256, so offline verification requires trusted shared-secret key material.

## ZIP Bundle
`format=zip` returns an archive containing:
- `bundle.json`
- `integrity.json`
- `decision_snapshot.json`
- `policy_snapshot.json`
- `input_snapshot.json`
- `override_snapshot.json`
- `ledger_segment.json`
- `checkpoint_snapshot.json`
- `chain_proof.json`
- `checkpoint_proof.json`

## Stability Rules
- Top-level JSON fields are stable in `proof_pack_v1`.
- ZIP entry names are stable in `proof_pack_v1`.
- Additive fields are allowed.
- Breaking changes require `proof_pack_v2`.
