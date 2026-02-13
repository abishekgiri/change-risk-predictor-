# Environment Variables

## Required In Production

| Variable | Description |
|---|---|
| `RELEASEGATE_STORAGE_BACKEND` | `postgres` for production deployments. |
| `RELEASEGATE_POSTGRES_DSN` | Postgres DSN used by API storage layer. |
| `RELEASEGATE_JWT_SECRET` | JWT signing secret for API auth. |
| `RELEASEGATE_JWT_ISSUER` | JWT issuer claim (`iss`) that API validates. |
| `RELEASEGATE_JWT_AUDIENCE` | JWT audience claim (`aud`) that API validates. |
| `RELEASEGATE_CHECKPOINT_SIGNING_KEY` | Checkpoint signing secret (current HMAC model). |
| `RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID` | Identifier attached to checkpoint signatures. |
| `RELEASEGATE_ROOT_SIGNING_KEY` | Ed25519 root signing key (PEM or 32-byte raw key in hex/base64) for manifest/root exports. |
| `RELEASEGATE_ROOT_KEY_ID` | Root key identifier embedded in key manifests and signed daily roots. |

## Recommended

| Variable | Default | Description |
|---|---:|---|
| `RELEASEGATE_AUTO_MIGRATE` | `true` | Auto-apply DB migrations on startup. |
| `RELEASEGATE_TENANT_ID` | _none_ | Default tenant id for local/dev fallback. |
| `RELEASEGATE_STRICT_MODE` | `false` | Missing-data behavior (`true` = fail-closed). |
| `RELEASEGATE_LEDGER_VERIFY_ON_STARTUP` | `false` | Verify override chain on startup. |
| `RELEASEGATE_LEDGER_FAIL_ON_CORRUPTION` | `true` | Block startup if chain verification fails. |
| `RELEASEGATE_LOG_LEVEL` | `INFO` | Logger level. |

## Rate Limiting

| Variable | Default |
|---|---:|
| `RELEASEGATE_RATE_LIMIT_WINDOW_SECONDS` | `60` |
| `RELEASEGATE_RATE_LIMIT_TENANT_DEFAULT` | `180` |
| `RELEASEGATE_RATE_LIMIT_IP_DEFAULT` | `300` |
| `RELEASEGATE_RATE_LIMIT_TENANT_HEAVY` | `20` |
| `RELEASEGATE_RATE_LIMIT_IP_HEAVY` | `40` |
| `RELEASEGATE_RATE_LIMIT_TENANT_WEBHOOK` | `300` |
| `RELEASEGATE_RATE_LIMIT_IP_WEBHOOK` | `600` |

## Cache Tuning (Phase 7)

| Variable | Default | Description |
|---|---:|---|
| `RELEASEGATE_POLICY_REGISTRY_CACHE_TTL_SECONDS` | `300` | Compiled policy cache TTL. |
| `RELEASEGATE_POLICY_REGISTRY_CACHE_MAX_ENTRIES` | `256` | Compiled policy cache cap. |
| `RELEASEGATE_TRANSITION_MAP_CACHE_TTL_SECONDS` | `300` | Transition map cache TTL. |
| `RELEASEGATE_TRANSITION_MAP_CACHE_MAX_ENTRIES` | `256` | Transition map cache cap. |
| `RELEASEGATE_ROLE_MAP_CACHE_TTL_SECONDS` | `300` | Role map cache TTL. |
| `RELEASEGATE_ROLE_MAP_CACHE_MAX_ENTRIES` | `256` | Role map cache cap. |
| `RELEASEGATE_ROLE_RESOLUTION_CACHE_TTL_SECONDS` | `180` | Role resolution cache TTL. |
| `RELEASEGATE_ROLE_RESOLUTION_CACHE_MAX_ENTRIES` | `2048` | Role resolution cache cap. |
