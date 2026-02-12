# Policy DSL Specification (`v1`)

This file is the canonical policy DSL and compiled policy target spec.

## 1. Compiler Target

Source DSL compiles to the canonical compiled policy JSON object below (no wrapper):

```json
{
  "policy_id": "SEC-PR-001",
  "version": "1.2.0",
  "name": "High Risk Requires Two Approvals",
  "description": "...",
  "scope": "pull_request",
  "enabled": true,
  "controls": [
    {"signal": "raw.risk_level", "operator": "in", "value": ["HIGH", "CRITICAL"]},
    {"signal": "features.approvals_count", "operator": "<", "value": 2}
  ],
  "enforcement": {"result": "BLOCK", "message": "High-risk changes require at least 2 approvals."},
  "evidence": {"include": ["raw.risk_level", "features.approvals_count"]},
  "metadata": {}
}
```

## 2. Base Schema

Required fields:
- `policy_id` (string)
- `version` (string)
- `name` (string)
- `controls` (array)
- `enforcement` (object)

Optional fields:
- `description` (string)
- `scope` (`pull_request` | `commit`, default `pull_request`)
- `enabled` (bool, default `true`)
- `evidence` (object)
- `metadata` (object)

`controls[]`:
- `signal` (string, dot path)
- `operator` (`>`, `>=`, `<`, `<=`, `==`, `!=`, `in`, `not in`)
- `value` (JSON value)

`enforcement`:
- `result` (`BLOCK`, `WARN`, `COMPLIANT`)
- `message` (string, optional)

Unknown fields are forbidden.

## 3. Normalization Rules

Normalization before hashing/evaluation:

- Fill defaults:
  - `scope="pull_request"`
  - `enabled=true`
- Preserve `controls[]` order as authored.
- Preserve `evidence.include[]` order as authored.
- Canonical serialization for hashing uses:
  - UTF-8
  - `sort_keys=true`
  - separators `(',', ':')`
- Bundle-level canonicalization sorts policies by `policy_id` ascending.

## 4. Operator Semantics

- Missing/`null` `actual` => condition is `false`.
- Numeric operators cast both sides to float.
- `in` with list-valued `actual` => true if any actual item is in expected set.
- `not in` with list-valued `actual` => true if all actual items are not in expected set.

## 5. Overlay and Precedence Rules

Effective config resolution order:

1. Organization base config
2. Repository overlay (repo wins)
3. Matched scoped overlays in `policy_registry.scopes[]` (broad to narrow; later wins)

Merge semantics:

- Scalars: replace.
- Objects: deep merge recursively.
- Arrays/lists: replace whole list.
- Omission does not remove inherited keys.

Removal semantics:

- Rule removal is allowed only by explicit list replacement.
- Example: org `required_policies=[A,B]`, repo `required_policies=[A]` results in `[A]`.

Conflict examples (explicit):

- If org requires 2 approvals and repo overlay sets 1, effective value is 1.
- If repo does not set approvals, org value remains.

## 6. Validation Errors

Compiler/loader should emit stable error codes and messages:

| Code | Message Template |
|---|---|
| `RG_POL_001` | `Missing required field: {field}` |
| `RG_POL_002` | `Unknown field not allowed: {field}` |
| `RG_POL_003` | `Invalid operator: {operator}` |
| `RG_POL_004` | `Invalid enforcement result: {result}` |
| `RG_POL_005` | `Duplicate policy_id: {policy_id}` |
| `RG_POL_006` | `No policies loaded from {policy_dir}` |
| `RG_POL_007` | `Failed to parse policy file {path}: {error}` |
| `RG_POL_008` | `Invalid scope selector key: {key}` |

## 7. Versioning and Compatibility

- `policy_id` is stable identity.
- `version` is author-managed evolution marker.
- Additive fields are allowed in `v1`.
- Removing or changing existing field/operator semantics is breaking and requires DSL major version bump.
- `policy_hash` and `policy_bundle_hash` must remain stable for semantically identical canonical inputs.
