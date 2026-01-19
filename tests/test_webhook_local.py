from fastapi.testclient import TestClient
from riskbot.server import app
from riskbot.config import RISK_DB_PATH
import sqlite3
import os
import json

client = TestClient(app)

def test_webhook_pr_opened():
    """
    Simulates a PR opened webhook event.
    """
    # 1. Payload
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 999,
            "title": "Integration Test PR",
            "body": "Testing the webhook",
            "state": "open",
            "user": {"login": "test-bot"},
            "base": {"sha": "base123"},
            "head": {"sha": "head123"},
            "merged": False
        },
        "repository": {
            "full_name": "test/webhook-repo"
        }
    }
    
    # 2. Post
    # We skip signature because env var GITHUB_WEBHOOK_SECRET is likely not set in CI
    response = client.post(
        "/webhooks/github",
        json=payload,
        headers={"X-GitHub-Event": "pull_request"}
    )
    
    assert response.status_code == 200, f"Response: {response.text}"
    data = response.json()
    assert data["status"] == "processed"
    assert "risk_score" in data
    
    # 3. Verify DB
    conn = sqlite3.connect(RISK_DB_PATH)
    row = conn.execute(
        "SELECT * FROM pr_runs WHERE repo=? AND pr_number=?", 
        ("test/webhook-repo", 999)
    ).fetchone()
    conn.close()
    
    assert row is not None, "PR run not saved to DB"
    print("Success: Webhook processed and Run saved to DB!")

def test_webhook_ping():
    """Test GitHub Ping event."""
    response = client.post(
        "/webhooks/github",
        json={"zen": "Non-blocking is better than blocking."},
        headers={"X-GitHub-Event": "ping"}
    )
    assert response.status_code == 200
    assert response.json() == {"msg": "pong"}
    print("Success: Ping event handled!")

if __name__ == "__main__":
    test_webhook_ping()
    test_webhook_pr_opened()
