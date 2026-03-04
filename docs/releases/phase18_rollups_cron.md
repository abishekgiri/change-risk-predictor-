# Phase 18 Rollups Cron

Run nightly rollup backfill to keep dashboard trends current.

## Endpoint

`POST /internal/dashboard/rollups/backfill?days=2`

## Headers

- `Authorization: Bearer <ADMIN_TOKEN>`
- `X-Request-Id: <uuid>`

## Schedule

- Nightly UTC (recommended)
- Retry policy: 2 retries

## Notes

- `days=2` is intentional to include late-arriving events.
- The endpoint is idempotent and safe to retry.
