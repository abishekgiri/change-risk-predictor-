# Forge Production Hardening

This document defines ReleaseGate's Jira-Forge runtime hardening behavior.

## Structured Logging Contract

Each transition evaluation emits structured JSON logs with:

- `tenant_id`
- `decision_id` (or `pending` before decision creation)
- `request_id`
- `issue_key`
- `transition_id`
- `policy_bundle_hash`
- `mode` (`strict`/`permissive`)
- `result` (`ALLOWED`/`BLOCKED`/`SKIPPED`/`ERROR`)
- `reason_code`

Error logs include `error_code`.

## Dependency Failure Behavior

| Failure Mode | Permissive (`strict_mode=false`) | Strict (`strict_mode=true`) | Reason Code |
|---|---|---|---|
| Jira dependency timeout | `SKIPPED` (allow) | `BLOCKED` | `SKIPPED_TIMEOUT` / `TIMEOUT_DEPENDENCY` |
| Policy registry timeout | `SKIPPED` (allow) | `BLOCKED` | `SKIPPED_TIMEOUT` / `TIMEOUT_DEPENDENCY` |
| Storage timeout while persisting decision | `SKIPPED` (allow) | `BLOCKED` | `SKIPPED_TIMEOUT` / `TIMEOUT_DEPENDENCY` |
| Missing risk metadata | `SKIPPED` (allow) | `BLOCKED` | `MISSING_RISK_METADATA` / `MISSING_RISK_METADATA_STRICT` |
| Missing transition policy mapping | `SKIPPED` (allow) | `BLOCKED` | `NO_POLICIES_MAPPED` / `NO_POLICIES_MAPPED_STRICT` |
| Invalid policy reference | `SKIPPED` (allow) | `BLOCKED` | `INVALID_POLICY_REFERENCE` / `INVALID_POLICY_REFERENCE_STRICT` |
| Internal system error | `ERROR` decision + env-aware allow/block | `ERROR` decision + fail-closed in production | `SYSTEM_ERROR` |

Decision semantics are source-of-truth in `docs/decision-model.md`.

## Deploy-Time Policy Bundle Validation

Run this before Forge deploy:

```bash
python -m releasegate.cli validate-policy-bundle
```

This command validates:

- compiled policy schema integrity
- logical lint checks (duplicate IDs, contradictions, ambiguous overlaps)

Deploy must fail on non-zero exit.
