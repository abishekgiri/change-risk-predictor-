# Decision Model Specification (`v1`)

This file is the single source of truth for decision semantics.

- Canonical owner of decision output fields: this document.
- Canonical owner of `reason_code` meanings: this document.
- Canonical owner of strict vs permissive behavior: this document.

Other docs must reference this file and must not redefine these semantics.

## Related Contract Sources

- Attestation schema source of truth: `releasegate/attestation/schema/release-attestation.v1.json`
- Attestation canonicalization source of truth: `releasegate/attestation/canonicalize.py`
- Proofpack schema contract: `docs/contracts/proof_pack_v1.md`

## Inputs
Evaluator input is a 4-part snapshot:

1. `policy_snapshot`
- Type: `array<object>`
- Required: yes
- Description: policy bindings used for evaluation.

2. `input_snapshot`
- Type: `object`
- Required: yes
- Description: runtime signal and request snapshot used for replay.

3. `context`
- Type: `object`
- Required: yes
- Description: transition, actor, and repository context.

4. `override_state`
- Type: `object`
- Required: yes
- Description: override eligibility and approval state.

## Output Contract
Decision output is split into two parts:

- `envelope` (non-deterministic metadata)
- `deterministic_payload` (deterministic policy outcome)

### Envelope Fields

| Field | Type | Required | Example | Notes |
|---|---|---|---|---|
| `decision_id` | `string` (UUID v4) | yes | `"f7b67225-d2f5-49a8-bf53-274bdfce24a6"` | Generated once at decision creation. Immutable. Not deterministic across fresh re-runs. |
| `timestamp` | `string` (UTC RFC3339) | yes | `"2026-02-12T08:31:52.613456+00:00"` | Creation time. Immutable. Excluded from deterministic comparisons. |
| `context_id` | `string` | yes | `"jira-PAY-1842"` | Deterministic context reference. |
| `evaluation_key` | `string` (hex SHA-256) | yes | `"32ffb350fe2f..."` | Deterministic idempotency key from normalized transition tuple. |

### Deterministic Payload Fields

| Field | Type | Required | Example | Notes |
|---|---|---|---|---|
| `release_status` | `enum` | yes | `"BLOCKED"` | One of `ALLOWED`, `BLOCKED`, `CONDITIONAL`, `SKIPPED`, `ERROR`. |
| `reason_code` | `string` | yes | `"MISSING_RISK_METADATA"` | Stable machine-readable reason. |
| `message` | `string` | yes | `"SKIPPED: missing issue property releasegate_risk"` | Human-readable decision text. |
| `policy_bundle_hash` | `string` (hex SHA-256) | yes | `"d4e7c63e..."` | Hash of bound policy identities (see hashing section). |
| `policy_bindings` | `array<object>` | yes | `[{"policy_id":"SEC-PR-001","policy_version":"1.2.0","policy_hash":"..."}]` | Bound policies used for decision and replay. |
| `matched_policies` | `array<string>` | yes | `["SEC-PR-001"]` | Policies triggered by the input. |
| `blocking_policies` | `array<string>` | yes | `["SEC-PR-001"]` | Subset of matched policies that force block. |
| `inputs_present` | `object<string,bool>` | yes | `{"releasegate_risk": true}` | Input presence map for audit clarity. |
| `input_snapshot` | `object` | yes | `{"signal_map": {...}, "policies_requested": ["SEC-PR-001"]}` | Replay snapshot. |
| `unlock_conditions` | `array<string>` | yes | `["Request 2 approvals including Security"]` | Human actions to unblock. |
| `policy_bindings[].policy_id` | `string` | yes | `"SEC-PR-001"` | Stable logical identifier. |
| `policy_bindings[].policy_version` | `string` | yes | `"1.2.0"` | Author-declared version. |
| `policy_bindings[].policy_hash` | `string` (hex SHA-256) | yes | `"ab91dd..."` | Hash of canonical compiled policy JSON. |

## Reason Codes (`v1`)

| Code | Meaning |
|---|---|
| `POLICY_ALLOWED` | Policy evaluation passed. |
| `POLICY_CONDITIONAL` | Warning state; allowed with conditions. |
| `POLICY_BLOCKED` | Policy evaluation blocked release. |
| `POLICY_SKIPPED` | Policy evaluation skipped. |
| `MISSING_RISK_METADATA` | Required risk metadata missing (permissive mode). |
| `MISSING_RISK_METADATA_STRICT` | Required risk metadata missing (strict mode blocks). |
| `NO_POLICIES_MAPPED` | No transition policies mapped (permissive mode). |
| `NO_POLICIES_MAPPED_STRICT` | No transition policies mapped (strict mode blocks). |
| `INVALID_POLICY_REFERENCE` | Transition references unresolved policy IDs (permissive mode). |
| `INVALID_POLICY_REFERENCE_STRICT` | Transition references unresolved policy IDs (strict mode blocks). |
| `OVERRIDE_APPLIED` | Approved override applied. |
| `OVERRIDE_EXPIRED` | Override request expired. |
| `OVERRIDE_JUSTIFICATION_REQUIRED` | Override requested without required justification. |
| `SOD_PR_AUTHOR_CANNOT_OVERRIDE` | Override blocked by separation-of-duties (PR author). |
| `SOD_REQUESTOR_CANNOT_SELF_APPROVE` | Override blocked by separation-of-duties (requestor self-approval). |
| `RISK_METADATA_FETCH_ERROR` | Risk metadata retrieval failed. |
| `TIMEOUT_DEPENDENCY` | Dependency timed out in strict mode (blocks transition). |
| `SKIPPED_TIMEOUT` | Dependency timed out in permissive mode (audited skip/allow). |
| `SYSTEM_ERROR` | Internal evaluation/enforcement error. |

## Hashing Rules

`policy_bundle_hash` is SHA-256 over canonical JSON:

1. For each bound policy, compute `policy_hash` as SHA-256 over canonical JSON of the compiled policy object.
2. Build array of:
   - `policy_id`
   - `policy_version`
   - `policy_hash`
3. Sort array by `policy_id` ascending.
4. Serialize canonical JSON with:
   - UTF-8
   - `sort_keys=true`
   - separators `(',', ':')`
5. Hash serialized bytes with SHA-256 to produce `policy_bundle_hash`.

## Determinism Contract (Testable)

For identical normalized inputs (`policy_snapshot`, `input_snapshot`, `context`, `override_state`) and identical mode flags:

- `deterministic_payload` MUST be byte-for-byte identical when canonicalized.
- Canonicalization rules for tests:
  - UTF-8
  - `sort_keys=true`
  - separators `(',', ':')`
  - exclude envelope fields (`decision_id`, `timestamp`)

Ordering rules:

- Policy evaluation order is deterministic by policy ID ascending.
- `policy_bindings` order is policy ID ascending.
- `matched_policies` and `blocking_policies` preserve deterministic evaluation order.
- Operator semantics are fixed (`==`, `!=`, `>`, `>=`, `<`, `<=`, `in`, `not in`).

## Strict vs Permissive Behavior

| Condition | Permissive (`strict_mode=false`) | Strict (`strict_mode=true`) |
|---|---|---|
| Missing risk metadata | `SKIPPED` + `MISSING_RISK_METADATA` | `BLOCKED` + `MISSING_RISK_METADATA_STRICT` |
| No policies mapped | `SKIPPED` + `NO_POLICIES_MAPPED` | `BLOCKED` + `NO_POLICIES_MAPPED_STRICT` |
| Invalid policy reference | `SKIPPED` + `INVALID_POLICY_REFERENCE` | `BLOCKED` + `INVALID_POLICY_REFERENCE_STRICT` |
| Dependency timeout (Jira/policy/storage) | `SKIPPED` + `SKIPPED_TIMEOUT` | `BLOCKED` + `TIMEOUT_DEPENDENCY` |
| Override SoD violation | `BLOCKED` | `BLOCKED` |
| Expired/missing override justification | `BLOCKED` | `BLOCKED` |
| Internal system error | `ERROR` decision recorded; enforcement allow/deny based on strictness and environment | `ERROR` decision recorded; production behavior remains fail-closed |
