# RiskBot V3 ML Integration Walkthrough

We have successfully enabled the Machine Learning capabilities for RiskBot. Previously, the system was stuck in a "Cold Start" problem where we couldn't train a model without data, but couldn't get data easily without using the tool.

## Achievements
1.  **Mock Data Generation**: Created `riskbot/utils/mock_data.py` to seed the database with 60 simulated PR runs and labels.
2.  **Model Training**: Successfully trained a LogisticRegression model using the mock data.
    *   Result: `data/model.pkl` generated.
3.  **Hybrid Inference**: Verified that `riskbot/main.py` now automatically loads the model and incorporates its prediction into the final risk score.
4.  **Testing**: Improved `tests/test_dashboard_smoke.py` to verify database health instead of a placeholder.
5.  **Webhook Integration**: Implemented `riskbot/server.py` (FastAPI) to receive real GitHub PR events and store them in the database.

## Verification
### 1. Test Execution
Ran `pytest tests/test_dashboard_smoke.py`:
```
tests/test_dashboard_smoke.py .                                          [100%]
1 passed
```

Ran `python3 tests/test_webhook_local.py`:
```
Success: Ping event handled!
Processing PR #999 for test/webhook-repo (opened)
Saved run to DB: data/riskbot.db
Success: Webhook processed and Run saved to DB!
```

### 3. Live Webhook Check (ngrok)
Pushed a commit to `riskbot-test` branch and verified database ingestion:
```
sqlite3 data/riskbot.db "SELECT ... FROM pr_runs ..."
# Output:
abishekgiri/change-risk-predictor-|4|2026-01-19 06:24:02|25  <-- CONFIRMED REAL DATA
```

### 2. Live Inference Check
Ran `python3 riskbot/main.py --base HEAD~1 --head HEAD` on the codebase itself:
```
## Change Risk Score: 50 (MEDIUM)

**Top reasons:**
- Touched critical path(s): auth/
- Large change size (+542 / -21 LOC)
- ML Model Risk Prediction: 8%  <-- CONFIRMED
```

## Next Steps
-   **Dashboard**: You can now run `streamlit run riskbot/dashboard/app.py` and see the "ML Ready" state.
-   **Real Data**: As real PRs are merged, the `pr_runs` table will populate with real data, eventually allowing you to re-train on real signals instead of mock data.
