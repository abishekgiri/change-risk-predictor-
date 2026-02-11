import unittest.mock
from fastapi.testclient import TestClient
from releasegate.server import app
from releasegate.config import DB_PATH
import sqlite3
import json
import hmac
import hashlib

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
            "title": "Integration Test PR PROJ-123",
            "body": "Testing the webhook for PROJ-123",
            "state": "open",
            "user": {"login": "test-bot"},
            "base": {"sha": "base123"},
            "head": {"sha": "head123"},
            "changed_files": 25,
            "additions": 20,
            "deletions": 5,
            "merged": False
        },
        "repository": {
            "full_name": "test/webhook-repo"
        }
    }
    
    # 2. Post
    # Generate signature
    secret = "mock_secret"
    # Ensure consistent JSON serialization
    payload_bytes = json.dumps(payload).encode('utf-8')
    mac = hmac.new(secret.encode(), msg=payload_bytes, digestmod=hashlib.sha256)
    signature = "sha256=" + mac.hexdigest()

    with unittest.mock.patch("releasegate.server.GITHUB_SECRET", secret), \
         unittest.mock.patch("releasegate.integrations.jira.client.JiraClient") as jira_client_cls:
        jira_client = jira_client_cls.return_value
        jira_client.set_issue_property.return_value = True

        response = client.post(
            "/webhooks/github",
            content=payload_bytes,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": signature,
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 200, f"Response: {response.text}"
        data = response.json()
        assert data["status"] == "processed"
        assert data["severity"] == "HIGH"
        assert "PROJ-123" in data["attached_issue_keys"]
        assert "risk_score" in data
        jira_client.set_issue_property.assert_called()
        
        # 3. Verify DB
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT * FROM pr_runs WHERE repo=? AND pr_number=?", 
            ("test/webhook-repo", 999)
        ).fetchone()
        conn.close()
        
        assert row is not None, "PR run not saved to DB"
        print("Success: Webhook processed and minimal run saved to DB!")

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
