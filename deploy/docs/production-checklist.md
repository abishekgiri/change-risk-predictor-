# Production Checklist

## Runtime

- Use `postgres` storage backend (`RELEASEGATE_STORAGE_BACKEND=postgres`).
- Configure `RELEASEGATE_POSTGRES_DSN` via secret manager (not `.env` in production).
- Confirm `/healthz` and `/readyz` are wired into load balancer checks.
- Confirm `/readyz` returns green only when DB + schema are ready.

## Security

- Store `RELEASEGATE_JWT_SECRET` in managed secrets.
- Store `RELEASEGATE_CHECKPOINT_SIGNING_KEY` in managed secrets.
- Rotate API keys and checkpoint keys on an operational schedule.
- Keep webhook signing keys tenant-scoped and rotate on compromise/suspicion.

## Data Integrity

- Enable `RELEASEGATE_LEDGER_VERIFY_ON_STARTUP=true`.
- Keep `RELEASEGATE_LEDGER_FAIL_ON_CORRUPTION=true` for strict environments.
- Run periodic `verify-proof-pack` checks on exported artifacts.

## Operations

- Back up Postgres with tested restore procedure.
- Define retention policy for audit artifacts and metrics events.
- Keep structured logs centrally collected and retained per policy.
- Set rate limits to environment-appropriate values.

## Pre-Release Verification

- `python -m releasegate.cli validate-policy-bundle`
- `python -m releasegate.cli validate-jira-config`
- `pytest -q`
