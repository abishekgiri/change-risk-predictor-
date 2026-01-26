# Phase 8: Packaging for Scale

## Overview
This document outlines the strategy for packaging `compliancebot` into a production-ready service, focusing on Dockerization and GitHub Action distribution.

## 1. Dockerized Service
**Goal:** Package the tool so it runs consistently on any machine, CI, or SaaS platform.

### Architecture
- **Base Image:** `python:3.10-slim` (Optimization for size)
- **Security:** Runs as non-root user `compliancebot` (UID 1000).
- **Permissions:** 
  - Source code in `/app` (Read-only for the process).
  - Runtime workspace in `/workspace`.
  - Artifacts always written to `/workspace/audit_bundles` to ensure compatibility with host volume mounts.

### Usage
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  -e GITHUB_TOKEN=... \
  ghcr.io/abishekgiri/change-risk-predictor:v1 \
  compliancebot analyze-pr --repo owner/repo --pr 123
```

## 2. GitHub Action Marketplace Listing
**Goal:** Make the tool installable via a single workflow step.

### Interface
```yaml
uses: abishekgiri/change-risk-predictor-@v1
with:
  repo: ${{ github.repository }}   # Auto-detected
  pr: ${{ github.event.pull_request.number }} # Auto-detected
  mode: report_only                # report_only | block
```

### Enforcement Logic
- **report_only**: Always returns Exit Code 0 (Success). Generates reports/comments but does not block merging.
- **block**: Returns Exit Code 1 (Failure) if the Compliance Engine returns a `FAIL` decision. This blocks the PR merge via branch protection rules.

## 3. SaaS Deployment (Future)
- **Architecture:** API/Worker split.
- **Ingestion:** GitHub App Webhook -> Queue -> Worker (Docker Container).
- **Storage:** Database for run history, S3/Blob for artifact bundles.

## 4. Multi-Repo Support (Future)
- **Registry:** Central database tracking onboarded repos.
- **Inheritance:** Org-level defaults overridden by Repo-level configs.
- **Normalization:** Standardized naming for status checks across the fleet.

## 5. Org-Wide Enforcement (Future)
- **Mechanism:** GitHub App Installation.
- **Governance:** "Required Status Check" enforced globally or by org policy.
- **Audit:** Immutable log of policy changes and override events.
