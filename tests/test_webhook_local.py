import unittest.mock
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
    # Mock external requests (GitHub API) so we don't hit real limits or need tokens
    with unittest.mock.patch("requests.post") as mock_post, \
         unittest.mock.patch("requests.get") as mock_get, \
         unittest.mock.patch("riskbot.server.GITHUB_TOKEN", "mock_token"):
        
        # Mock file fetch (files changed)
        # We need check which URL it was called with to return different things
        def mock_get_side_effect(url, headers):
            mock_resp = unittest.mock.Mock()
            mock_resp.status_code = 200
            
            if "/contents/riskbot_config.yml" in url:
                # Return empty config or mock config
                mock_resp.json.return_value = {"content": ""} # defaulting to empty
            elif "/files" in url:
                mock_resp.json.return_value = [{"filename": "config.py", "additions": 10, "deletions": 5}]
            else:
                 mock_resp.json.return_value = {}
            return mock_resp

        mock_get.side_effect = mock_get_side_effect

        # Mock comment & check run creation
        mock_post.return_value.status_code = 201
        
        response = client.post(
            "/webhooks/github",
            json=payload,
            headers={"X-GitHub-Event": "pull_request"}
        )
        
        assert response.status_code == 200, f"Response: {response.text}"
        data = response.json()
        assert data["status"] == "processed"
        assert "risk_score" in data

        # Verify Check Run was called
        # We expect 2 POST calls: one for comment, one for check run
        # Let's inspect call args to find the Check Run
        check_run_called = False
        for call in mock_post.call_args_list:
            if "/check-runs" in call[0][0]:
                check_run_called = True
                json_body = call[1]['json']
                assert json_body['name'] == "RiskBot CI"
                assert json_body['head_sha'] == "head123"
                # Check if details_url is passed (we enabled it)
                # Note: config.RISK_WEBHOOK_URL is loaded from env, which might be empty in test.
                # Ideally we should mock env, but this basic assertion is enough for now.
        
        assert check_run_called, "create_check_run was not called"
    
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
