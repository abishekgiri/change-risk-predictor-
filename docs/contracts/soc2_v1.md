# `soc2_v1` Export Contract

## Identity
- Contract ID: `soc2_v1`
- Endpoint: `GET /audit/export?contract=soc2_v1`
- Formats: `json`, `csv`

## JSON Response
Top-level object:
- `contract`: string, must be `soc2_v1`
- `schema_name`: string, `soc2_export`
- `schema_version`: string, `soc2_v1`
- `generated_at`: UTC timestamp string
- `tenant_id`: string
- `ids`: object
- `integrity`: object
- `repo`: string
- `records`: array of decision records
- `override_chain`: object, optional (present when `verify_chain=true`)

Top-level `integrity` fields:
- `canonicalization`: `releasegate-canonical-json-v1`
- `hash_alg`: `sha256`
- `input_hash`
- `policy_hash`
- `decision_hash`
- `replay_hash`
- `ledger.ledger_tip_hash`
- `ledger.ledger_record_id`
- `signatures.checkpoint_signature` (empty string in SOC2 export)
- `signatures.signing_key_id` (empty string in SOC2 export)

Decision record fields:
- `schema_name`: string, `soc2_record`
- `schema_version`: string, `soc2_v1`
- `generated_at`: UTC timestamp string
- `tenant_id`: string
- `ids`: object
- `decision_id`: string
- `decision`: enum (`ALLOWED`, `BLOCKED`, `CONDITIONAL`, `SKIPPED`, `ERROR`, `UNKNOWN`)
- `reason_code`: string

Decision semantics reference:
- `reason_code` semantics and strict/permissive interpretation are defined in `docs/decision-model.md`.
- `human_message`: string
- `actor`: string or `null`
- `policy_version`: string or `null`
- `inputs_present`: object
- `override_id`: string or `null`
- `chain_verified`: boolean or `null`
- `repo`: string
- `pr_number`: integer or `null`
- `created_at`: timestamp string
- `integrity`: object (per-decision hashes and ledger linkage)

## CSV Response
- Header fields match the JSON record keys.
- One row per decision record.

## Stability Rules
- Existing keys and semantics are stable for `soc2_v1`.
- Additive fields are allowed.
- Breaking changes require `soc2_v2`.
