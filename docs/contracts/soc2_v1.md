# `soc2_v1` Export Contract

## Identity
- Contract ID: `soc2_v1`
- Endpoint: `GET /audit/export?contract=soc2_v1`
- Formats: `json`, `csv`

## JSON Response
Top-level object:
- `contract`: string, must be `soc2_v1`
- `repo`: string
- `records`: array of decision records
- `override_chain`: object, optional (present when `verify_chain=true`)

Decision record fields:
- `decision_id`: string
- `decision`: enum (`ALLOWED`, `BLOCKED`, `CONDITIONAL`, `SKIPPED`, `ERROR`, `UNKNOWN`)
- `reason_code`: string
- `human_message`: string
- `actor`: string or `null`
- `policy_version`: string or `null`
- `inputs_present`: object
- `override_id`: string or `null`
- `chain_verified`: boolean or `null`
- `repo`: string
- `pr_number`: integer or `null`
- `created_at`: timestamp string

## CSV Response
- Header fields match the JSON record keys.
- One row per decision record.

## Stability Rules
- Existing keys and semantics are stable for `soc2_v1`.
- Additive fields are allowed.
- Breaking changes require `soc2_v2`.
