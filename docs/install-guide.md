# ReleaseGate Installation Guide

_From zero to enforcing governance in your first deployment in under 2 hours._

---

## Who This Guide Is For

| Reader | What you get |
|--------|-------------|
| **Evaluating ReleaseGate** | A 5-minute demo stack that shows every dashboard screen with realistic data |
| **Piloting in staging** | A 30-minute Docker Compose setup that connects to your Jira sandbox |
| **Deploying to production** | A step-by-step enterprise path with Postgres, key management, and CI integration |

---

## Path 1 — 5-Minute Demo (No Jira required)

The demo stack ships with pre-loaded fixture data for two demo tenants
(`demo` and `demo-risk`). No Jira, no API keys, no configuration.

```bash
# 1. Clone the repo
git clone https://github.com/your-org/releasegate.git
cd releasegate

# 2. Start everything
docker compose -f docker-compose.demo.yml up

# 3. Open the dashboard
open http://localhost:3000?tenant_id=demo
```

**What's running:**

| URL | Description |
|-----|-------------|
| `http://localhost:3000` | Governance dashboard |
| `http://localhost:8000` | REST API (Swagger at `/docs`) |
| `http://localhost:3000/ops` | SRE ops health view |

**Demo tenant `demo`** is healthy: recent risk signals, signed checkpoints, a mix of
allowed and blocked deployments.

**Demo tenant `demo-risk`** is at-risk: stale signal, no checkpoint, multiple blocked deploys.
The Ops Health page will show all three alert conditions firing.

Stop the demo: `docker compose -f docker-compose.demo.yml down -v`

---

## Path 2 — 30-Minute Staging Pilot

Connect ReleaseGate to your real Jira Cloud sandbox and wire in one CI pipeline.

### Prerequisites

- Docker ≥ 24 and Docker Compose v2
- A Jira Cloud sandbox URL and admin credentials
- A GitHub Actions (or GitLab) repository to test with

### Step 1 — Create a `.env` file

```bash
cp .env.example .env
```

Edit the values:

```dotenv
# Jira
JIRA_BASE_URL=https://your-org.atlassian.net
JIRA_USER_EMAIL=you@example.com
JIRA_API_TOKEN=<from https://id.atlassian.com/manage-profile/security/api-tokens>

# Auth
RELEASEGATE_AUTH_MODE=jwt
RELEASEGATE_JWT_SECRET=change-me-in-staging

# Storage (SQLite is fine for a pilot)
RELEASEGATE_DB_BACKEND=sqlite
RELEASEGATE_SQLITE_PATH=/data/releasegate.db

# Tenant
RELEASEGATE_DEFAULT_TENANT=your-org
```

### Step 2 — Start the stack

```bash
docker compose up
```

The API will be available at `http://localhost:8000`.

### Step 3 — Configure your first Jira project

```bash
# Create a policy for your project
curl -X POST http://localhost:8000/policies \
  -H "Authorization: Bearer $RELEASEGATE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-org",
    "project_key": "YOUR_PROJECT",
    "policy": {
      "require_approval_for_production": true,
      "block_stale_signal": true,
      "signal_max_age_hours": 2
    }
  }'
```

### Step 4 — Wire in CI

Copy `examples/ci/github-actions.yml` (or `gitlab-ci.yml`) into your repository.
Set two secrets in your CI settings:

| Secret | Value |
|--------|-------|
| `RELEASEGATE_URL` | `http://your-host:8000` |
| `RELEASEGATE_TOKEN` | Your API token |

And one variable:

| Variable | Value |
|----------|-------|
| `JIRA_ISSUE_KEY` | e.g. `YOUR_PROJECT-42` |
| `JIRA_PROJECT_KEY` | e.g. `YOUR_PROJECT` |

Open a pull request — ReleaseGate will evaluate the deployment gate and post
a result to the CI check.

### Step 5 — Open the dashboard

```
http://localhost:3000?tenant_id=your-org
```

You should see the Trust & Audit page populating with decisions from your test PRs.

---

## Path 3 — Production Deployment (Enterprise)

### Architecture overview

```
                       ┌──────────────────────────────┐
                       │  Your CI pipelines           │
                       │  (GitHub / GitLab / Jenkins) │
                       └──────────────┬───────────────┘
                                      │ HTTPS
                       ┌──────────────▼───────────────┐
        ┌──────────────►  ReleaseGate API (FastAPI)   ◄──── Dashboard (Next.js)
        │              │  Port 8000                   │
        │              └──────────────┬───────────────┘
        │                             │
        │              ┌──────────────▼───────────────┐
        │              │  PostgreSQL 15               │
        │              │  Append-only audit tables    │
        │              └──────────────────────────────┘
        │
Jira Cloud / Server
```

### Infrastructure requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| API server | 2 vCPU / 2 GB RAM | 4 vCPU / 8 GB RAM |
| Database | PostgreSQL 15, 50 GB SSD | PostgreSQL 15, 200 GB SSD + PITR backups |
| Dashboard | 1 vCPU / 1 GB RAM | 2 vCPU / 2 GB RAM |
| Network | Outbound HTTPS to Jira | VPC with private subnets recommended |

### Step 1 — Provision PostgreSQL

ReleaseGate requires a dedicated database with:

```sql
CREATE DATABASE releasegate;
CREATE USER releasegate WITH PASSWORD 'strong-password';
GRANT ALL PRIVILEGES ON DATABASE releasegate TO releasegate;
```

Append-only protections are applied automatically via triggers on first `init_db`.

### Step 2 — Environment variables

```dotenv
# Database
RELEASEGATE_DB_BACKEND=postgres
DATABASE_URL=postgresql://releasegate:strong-password@db-host:5432/releasegate

# Authentication — use a proper JWKS endpoint in production
RELEASEGATE_AUTH_MODE=jwt
RELEASEGATE_JWT_SECRET=<256-bit secret>

# Jira
JIRA_BASE_URL=https://your-org.atlassian.net
JIRA_USER_EMAIL=releasegate-svc@your-org.com
JIRA_API_TOKEN=<service account token>

# Signing keys (for audit checkpoints)
RELEASEGATE_SIGNING_KEY_ID=prod-key-1
# Ed25519 private key (PEM) — store in your secrets manager
RELEASEGATE_SIGNING_PRIVATE_KEY_B64=<base64-encoded PEM>

# External anchoring (RFC 3161 TSA)
RELEASEGATE_RFC3161_TSA_URL=http://timestamp.digicert.com

# Ops alerting
RELEASEGATE_OPS_ALERT_ENABLED=true
RELEASEGATE_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
RELEASEGATE_OPS_ALERT_EMAIL_TO=oncall@your-org.com
RELEASEGATE_OPS_ALERT_COOLDOWN=3600

# Startup behaviour
LEDGER_VERIFY_ON_STARTUP=true
```

### Step 3 — Deploy the API

```bash
# Pull the image
docker pull ghcr.io/your-org/releasegate:latest

# Run migrations / init DB
docker run --rm \
  --env-file .env.prod \
  ghcr.io/your-org/releasegate:latest \
  python -c "from releasegate.storage.schema import init_db; init_db()"

# Start the API server
docker run -d \
  --name releasegate-api \
  -p 8000:8000 \
  --env-file .env.prod \
  --restart unless-stopped \
  ghcr.io/your-org/releasegate:latest \
  uvicorn releasegate.server:app --host 0.0.0.0 --port 8000 --workers 4
```

### Step 4 — Deploy the dashboard

```bash
# Build with your API URL baked in
docker build \
  --build-arg NEXT_PUBLIC_API_BASE_URL=https://api.releasegate.your-org.com \
  -t releasegate-dashboard:latest \
  ./dashboard-ui

docker run -d \
  --name releasegate-dashboard \
  -p 3000:3000 \
  -e RELEASEGATE_BACKEND_URL=http://releasegate-api:8000 \
  -e RELEASEGATE_TOKEN=$RELEASEGATE_SERVICE_TOKEN \
  --restart unless-stopped \
  releasegate-dashboard:latest
```

### Step 5 — Configure DNS and TLS

Place both services behind your reverse proxy (nginx, Caddy, AWS ALB) with:
- TLS termination
- `api.releasegate.your-org.com` → port 8000
- `releasegate.your-org.com` → port 3000
- CORS header: `Access-Control-Allow-Origin: https://releasegate.your-org.com`

### Step 6 — Add the CI gate to all production pipelines

See [examples/ci/](../examples/ci/) for templates for GitHub Actions, GitLab CI,
and Jenkins. Set secrets in each CI system:

```
RELEASEGATE_URL   = https://api.releasegate.your-org.com
RELEASEGATE_TOKEN = <token with policy:read scope>
```

### Step 7 — Verify the installation

```bash
# Health check
curl https://api.releasegate.your-org.com/health

# Trust status for your first tenant
curl -H "Authorization: Bearer $TOKEN" \
  https://api.releasegate.your-org.com/audit/trust-status?tenant_id=your-org

# Ops system health
curl -H "Authorization: Bearer $TOKEN" \
  https://api.releasegate.your-org.com/ops/system-health
```

Expected trust-status output (healthy):

```json
{
  "trust_score": 95,
  "checkpoint": { "ok": true, "age_hours": 1.2 },
  "signal": { "fresh": true },
  "ledger": { "valid": true }
}
```

---

## Atlassian Forge / Marketplace Install

If you are installing from the Atlassian Marketplace:

1. Go to **Jira Settings → Apps → Find new apps**
2. Search for **ReleaseGate**
3. Click **Get app** → **Grant permissions**
4. Navigate to the ReleaseGate configuration screen in your Jira settings
5. Enter your API URL and token (or use the hosted SaaS option)

See [docs/forge-installation.md](forge-installation.md) for a complete Forge
setup walkthrough including webhook configuration and permission scopes.

---

## Ops Monitoring

Once deployed, the SRE ops health dashboard at `/ops` shows:

- Decision throughput and block rate (configurable time window)
- Checkpoint coverage across all tenants
- Active alert conditions (stale signal, missed checkpoint, blocked deploys)
- DB health

Alert channels are configured via environment variables:

| Variable | Description |
|----------|-------------|
| `RELEASEGATE_SLACK_WEBHOOK_URL` | Slack incoming webhook |
| `RELEASEGATE_OPS_ALERT_EMAIL_TO` | Comma-separated email recipients |
| `RELEASEGATE_OPS_ALERT_WEBHOOK_URL` | Generic JSON webhook |
| `RELEASEGATE_OPS_ALERT_COOLDOWN` | Seconds between repeat alerts (default 3600) |
| `RELEASEGATE_OPS_ALERT_ENABLED` | Master switch (`true`/`false`) |

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `/health` returns 500 | DB connection: verify `DATABASE_URL` and Postgres is reachable |
| Trust score stuck at 0 | Run `POST /internal/anchor/tick?tenant_id=...` to trigger checkpoint |
| CI gate always BLOCKED | Verify token scopes include `policy:read`; check `/audit/trust-status` |
| Stale signal alert firing | Confirm risk signals are being written to `audit_decisions`; check worker logs |
| Dashboard shows no data | Confirm `RELEASEGATE_BACKEND_URL` in dashboard container points to the API |

For additional help see [docs/AUDITOR_QUICKSTART.md](AUDITOR_QUICKSTART.md)
or open an issue at [github.com/your-org/releasegate](https://github.com/your-org/releasegate).
