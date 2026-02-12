# `proof_pack_v1` Format

## Identity
- Artifact ID: `proof_pack_v1`
- Endpoint: `GET /audit/proof-pack/{decision_id}`
- Formats: `json`, `zip`
- On-wire bundle version: `audit_proof_v1`

## JSON Bundle
Top-level fields:
- `bundle_version`: string, currently `audit_proof_v1`
- `generated_at`: UTC timestamp string
- `decision_id`: string
- `repo`: string or `null`
- `pr_number`: integer or `null`
- `decision_snapshot`: object
- `policy_snapshot`: array
- `input_snapshot`: object
- `override_snapshot`: object or `null`
- `chain_proof`: object or `null`
- `checkpoint_proof`: object or `null`

## ZIP Bundle
`format=zip` returns an archive containing:
- `bundle.json`
- `decision_snapshot.json`
- `policy_snapshot.json`
- `input_snapshot.json`
- `override_snapshot.json`
- `chain_proof.json`
- `checkpoint_proof.json`

## Stability Rules
- Top-level JSON fields are stable in `proof_pack_v1`.
- ZIP entry names are stable in `proof_pack_v1`.
- Additive fields are allowed.
- Breaking changes require `proof_pack_v2`.
