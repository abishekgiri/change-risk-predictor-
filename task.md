# RiskBot V3 Task List

- [x] **ML Integration**
    - [x] Create mock data generator (`riskbot/utils/mock_data.py`)
    - [x] Generate mock data and train initial model
    - [x] Verify hybrid scoring logic in `main.py`
    - [x] Fix dashboard smoke tests

- [x] **GitHub Webhook Integration**
    - [x] Implement FastAPI server (`riskbot/server.py`)
    - [x] Handle `ping` events explicitly (fix 404)
    - [x] Verify local webhook handling with `tests/test_webhook_local.py`
    - [x] Verify real-time ingestion via `ngrok` (Push test confirmed)

- [ ] **CI Integration**
    - [ ] Create `.github/workflows/risk_check.yml`
    - [ ] Add `PyGithub` to `requirements.txt`
