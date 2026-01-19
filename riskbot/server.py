import hmac
import hashlib
import json
import os
import requests
from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel
from typing import Optional, Dict, Any
from riskbot.scoring.rules_v1 import calculate_score
from riskbot.storage.sqlite import save_run

# Initialize App
app = FastAPI(title="RiskBot Webhook Listener")

# --- Config ---
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")  # Use user's preferred default
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")                # For API calls

def get_pr_files(repo_full_name: str, pr_number: int):
    """Fetch files changed in PR using GitHub API."""
    if not GITHUB_TOKEN:
        print("Warning: No GITHUB_TOKEN, cannot fetch file details.")
        return [], {"files_changed": 0, "loc_added": 0, "loc_deleted": 0}

    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"Failed to fetch files: {resp.status_code}")
            return [], {}
            
        files_data = resp.json()
        filenames = [f['filename'] for f in files_data]
        
        # Calculate diff stats from file list
        added = sum(f.get('additions', 0) for f in files_data)
        deleted = sum(f.get('deletions', 0) for f in files_data)
        
        return filenames, {
            "files_changed": len(files_data),
            "loc_added": added,
            "loc_deleted": deleted
        }
    except Exception as e:
        print(f"Error fetching files: {e}")
        return [], {}

@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
):
    payload = await request.body()

    # ✅ Handle GitHub ping FIRST
    if x_github_event == "ping":
        return {"msg": "pong"}  # <-- THIS FIXES 404

    # 🔐 Verify signature
    if GITHUB_SECRET:
        mac = hmac.new(
            GITHUB_SECRET.encode(),
            msg=payload,
            digestmod=hashlib.sha256
        )
        expected = "sha256=" + mac.hexdigest()

        if not hmac.compare_digest(expected, x_hub_signature_256 or ""):
            raise HTTPException(status_code=401, detail="Invalid signature")

    data = json.loads(payload)
    
    # Process Pull Request Events
    if x_github_event != "pull_request":
        return {"msg": "Ignored non-PR event"}

    action = data.get("action")
    if action not in ["opened", "synchronize", "reopened", "closed"]:
        return {"msg": f"Ignored PR action: {action}"}
        
    pr = data.get("pull_request", {})
    repo = data.get("repository", {})
    
    repo_full_name = repo.get("full_name")
    pr_number = pr.get("number")
    
    if not repo_full_name or not pr_number:
        return {"msg": "Missing repo or pr_number"}
        
    print(f"Processing PR #{pr_number} for {repo_full_name} ({action})")
    
    # Fetch Extra Features (Diff Stats)
    filenames, diff_stats = get_pr_files(repo_full_name, pr_number)
    
    # Basic Metadata
    base_sha = pr.get("base", {}).get("sha", "unknown")
    head_sha = pr.get("head", {}).get("sha", "unknown")
    title = pr.get("title", "")
    author = pr.get("user", {}).get("login", "unknown")
    
    # Construct Features for Scoring
    features = {
        "diff": diff_stats,
        "files": filenames,
        "churn": {"hotspots": []},
        "paths": [f for f in filenames if "config" in f or "auth" in f],
        "tests": any("test" in f for f in filenames),
        "metadata": {
            "title": title,
            "author": author,
            "state": pr.get("state"),
            "merged": pr.get("merged", False)
        }
    }
    
    # Calculate Score
    score_data = calculate_score(features)
    
    # Save to DB
    save_run(
        repo=repo_full_name,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        score_data=score_data,
        features=features
    )
    
    return {
        "status": "processed",
        "risk_score": score_data.get("score"),
        "risk_level": score_data.get("risk_level")
    }

@app.get("/")
def health_check():
    return {"status": "ok", "service": "RiskBot Webhook Listener"}
