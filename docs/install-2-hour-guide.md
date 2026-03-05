# ReleaseGate 2-Hour Installation Walkthrough

This walkthrough is designed for enterprise teams to install and validate ReleaseGate in under two hours.

## Prerequisites

- Docker 24+
- Node.js 20+
- Python 3.11+
- Jira admin access
- One test project/workflow in Jira

## 0:00-0:20 Setup

1. Clone repository.
2. Configure environment variables.
3. Confirm local prerequisites.

```bash
git clone https://github.com/abishekgiri/change-risk-predictor-.git
cd change-risk-predictor
cp deploy/docker-compose/.env.example deploy/docker-compose/.env
```

## 0:20-0:45 Deploy ReleaseGate

### Option A: Docker Compose

```bash
cd deploy/docker-compose
docker compose up --build
```

### Option B: Helm

```bash
helm install releasegate ./deploy/helm/releasegate
```

### Option C: Terraform (AWS)

```bash
cd infra/terraform/releasegate
terraform init
terraform apply
```

## 0:45-1:15 Configure Jira Integration

1. Install Forge app (see `docs/forge-installation.md`).
2. Connect Jira tenant in `/onboarding`.
3. Select protected projects/workflows/transitions.

## 1:15-1:40 Configure Policy and Run Simulation

1. Save onboarding setup.
2. Run 30-day historical simulation.
3. Review blocked percentage and override projection.

Recommended initial mode: `simulation`.

## 1:40-2:00 Validate Enforcement and Go Live

1. Set mode to `canary`.
2. Trigger protected transition from Jira.
3. Validate decision appears in `/overview`, `/observability`, and `/decisions/{id}`.
4. If stable, switch to `strict`.

## Operational Handoff Checklist

- Tenant status monitored (`active/locked/throttled`)
- Plan quotas reviewed in `/billing`
- Key rotation tested in `/tenant`
- Rollback tested in onboarding activation ladder
- SLA/failure mode docs shared with incident responders (`docs/sla_failure_modes.md`)

## Success Criteria

- ReleaseGate API healthy
- Jira integration active
- Transition checks enforced
- Audit/proof artifacts generated
- Team can execute rollback and key rotation
