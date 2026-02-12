# ReleaseGate Docker Compose

Fast path to run ReleaseGate API + Postgres locally.

## Start

From repository root:

```bash
cp deploy/compose/.env.example deploy/compose/.env
docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env up -d --build
```

## Verify

```bash
curl -sS http://localhost:8000/healthz
curl -sS http://localhost:8000/readyz
curl -sS http://localhost:8000/metrics
```

Expected:
- `/healthz` returns `200` when process is alive.
- `/readyz` returns `200` only when DB is reachable and schema is current.

## Validate policy + Jira config

```bash
python -m releasegate.cli validate-policy-bundle
python -m releasegate.cli validate-jira-config
```

## Stop

```bash
docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env down
```
