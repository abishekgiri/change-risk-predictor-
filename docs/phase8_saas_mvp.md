# Phase 8 Step 3: SaaS MVP Architecture

## Overview
The SaaS MVP enables "Zero Config" usage. Instead of users configuring GitHub Actions YAML, they simply **Install the GitHub App**. The App handles ingestion, analysis, and enforcement centrally.

## Core Components

### 1. API Service (The Receiver)
- **Role:** The entry point for all GitHub events.
- **Responsibility:**
  - Authenticate requests (Webhook Secret validation).
  - filter relevant events (`pull_request.opened`, `pull_request.synchronize`).
  - **Fast Handoff:** Does *no* analysis. Immediately pushes job to Queue.
- **Tech:** FastAPI + Uvicorn.

### 2. Job Queue ( The Buffer)
- **Role:** Decouples ingestion from processing. Handles bursts.
- **Tech:** Redis + RQ (Redis Queue).
- **Why:** GitHub expects fast webhook responses (<10s). Analysis takes time.

### 3. Worker Service (The Brain)
- **Role:** Executes the heavy `compliancebot` analysis.
- **Flow:**
  1. **Authenticate:** Generates an Installation Token for the specific Org/Repo.
  2. **Status: Pending:** Tells GitHub "ComplianceBot is running...".
  3. **Execute:** Runs the core engine (or Docker container).
  4. **Persist:** Saves the decision to the Audit DB.
  5. **Status: Final:** Tells GitHub "Pass" or "Fail" (Blocking the PR).

### 4. Database (The Audit Trail)
- **Role:** System of Record for compliance.
- **Schema:**
  - `installations`: Maps GitHub Installation IDs to Orgs.
  - `runs`: Immutable record of every analysis (PR, SHA, Decision, Timestamp).

## Deployment (MVP)
- **Single Node / Container Group:**
  - 1 Container: API
  - 1 Container: Worker
  - 1 Container: DB (Postgres)
  - 1 Container: Redis
- **Auth:** Application Private Key (`.pem`) used to sign JWTs for installation access.

## "Done" Criteria
1. User installs GitHub App.
2. User opens PR.
3. Webhook hits API.
4. Worker analyzes PR.
5. GitHub Status update appears on PR (Pass/Fail).
6. DB record created.
