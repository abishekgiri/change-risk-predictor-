import unittest.mock
from datetime import datetime, timezone
import uuid
from fastapi.testclient import TestClient
from releasegate.server import app
from releasegate.config import DB_PATH
import sqlite3
import json
import hmac
import hashlib
from releasegate.security.webhook_keys import create_webhook_key

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
    # Generate signatures
    secret = "mock_secret"
    signing_secret = "phase3-local-webhook-secret"
    signing_key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="github",
        created_by="test-suite",
        raw_secret=signing_secret,
        deactivate_existing=True,
    )
    # Ensure consistent JSON serialization
    payload_text = json.dumps(payload)
    payload_bytes = payload_text.encode('utf-8')
    mac = hmac.new(secret.encode(), msg=payload_bytes, digestmod=hashlib.sha256)
    signature = "sha256=" + mac.hexdigest()
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-opened-{uuid.uuid4().hex[:8]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/webhooks/github", payload_text])
    releasegate_signature = hmac.new(
        signing_secret.encode(),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

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
                "X-Signature": releasegate_signature,
                "X-Key-Id": signing_key["key_id"],
                "X-Timestamp": timestamp,
                "X-Nonce": nonce,
                "Content-Type": "application/json",
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
    signing_secret = "phase3-local-webhook-secret-ping"
    signing_key = create_webhook_key(
        tenant_id="tenant-test",
        integration_id="github",
        created_by="test-suite",
        raw_secret=signing_secret,
        deactivate_existing=True,
    )
    payload = {"zen": "Non-blocking is better than blocking."}
    payload_text = json.dumps(payload)
    payload_bytes = payload_text.encode("utf-8")
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = f"nonce-ping-{uuid.uuid4().hex[:8]}"
    canonical = "\n".join([timestamp, nonce, "POST", "/webhooks/github", payload_text])
    signature = hmac.new(signing_secret.encode(), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    response = client.post(
        "/webhooks/github",
        content=payload_bytes,
        headers={
            "X-GitHub-Event": "ping",
            "X-Signature": signature,
            "X-Key-Id": signing_key["key_id"],
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200
    assert response.json() == {"msg": "pong"}
    print("Success: Ping event handled!")

if __name__ == "__main__":
    test_webhook_ping()
    test_webhook_pr_opened()
