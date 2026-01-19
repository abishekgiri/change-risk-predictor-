# Webhook Ingestion Implementation Plan

## Goal
Implement a `POST /webhooks/github` endpoint that authenticates and parses GitHub Pull Request events, storing them in the local SQLite database so the dashboard displays real data.

## Proposed Changes

### 1. Dependencies
#### [MODIFY] [requirements.txt](file:///Users/abishekkumargiri/Desktop/sellable/change-risk-predictor:/requirements.txt)
- Add `fastapi`
- Add `uvicorn`
- Add `pydantic`

### 2. Webhook Server
#### [NEW] [riskbot/server.py](file:///Users/abishekkumargiri/Desktop/sellable/change-risk-predictor:/riskbot/server.py)
- **Framework**: FastAPI
- **Endpoint**: `POST /webhooks/github`
- **Security**: Verify `X-Hub-Signature-256` using `GITHUB_WEBHOOK_SECRET`.
- **Logic**:
    1. Parse `pull_request` event payload.
    2. Extract metadata: `repo`, `pr_number`, `title`, `author`, `created_at`.
    3. Calculate Risk Score: Call internal `calculate_score` (requires fetching file diffs via GitHub API).
    4. Save to `pr_runs` table in SQLite.

### 3. Database Schema
- Ensure existing schema supports the metadata (we might need to adding columns for `title` or `author` if they don't exist, or just store them in `features_json` for now to avoid migration headaches).
- *Decision*: Store extra metadata in `features_json` for V3 to keep schema simple.

## Verification Plan
### Automated Test
- Create `tests/test_webhook.py` using `fastapi.testclient.TestClient`.
- Simulate a `pull_request` `opened` payload.
- Assert that a row appears in `pr_runs` table.

### Manual Verification (User)
- User runs `uvicorn riskbot.server:app --reload`.
- User exposes via `ngrok`.
- User triggers a real PR event.
