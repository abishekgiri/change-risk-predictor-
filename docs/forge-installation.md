# Forge Installation Guide

This guide installs the ReleaseGate Forge app and connects it to a deployed ReleaseGate API.

## Prerequisites

- Atlassian organization admin access
- Node.js 20+
- Forge CLI access
- Deployed ReleaseGate API endpoint
- Internal service key or API token for ReleaseGate

## 1) Install Forge CLI

```bash
npm install -g @forge/cli
forge --version
```

## 2) Authenticate Forge

```bash
forge login
```

## 3) Configure app environment

From the Forge app folder (`forge/` in this repository):

```bash
cd forge
forge variables set RELEASEGATE_API_URL https://releasegate.example.com
forge variables set RELEASEGATE_SERVICE_KEY <your-service-key>
forge variables set RELEASEGATE_TENANT_ID <tenant-id>
```

## 4) Deploy app

```bash
forge deploy
```

## 5) Install into Jira

```bash
forge install
```

When prompted, choose the Jira site and product.

## 6) Validate end-to-end

- Trigger a Jira workflow transition protected by ReleaseGate.
- Confirm Forge app calls ReleaseGate check endpoint.
- Verify decision and evidence in the Governance Dashboard.

## Troubleshooting

- `401/403` from ReleaseGate: verify `RELEASEGATE_SERVICE_KEY` and tenant scope.
- Forge app not visible: verify install target site and product.
- Transition still bypassing: verify selected workflow IDs and transition IDs in onboarding.
