import hmac
import hashlib
import json
import os
import requests
import yaml
import base64
from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from riskbot.scoring.rules_v1 import calculate_score
from riskbot.scoring.rules_v1 import calculate_score
from riskbot.storage.sqlite import save_run
from riskbot.config import RISK_WEBHOOK_URL

# Initialize App
app = FastAPI(title="RiskBot Webhook Listener")

class CIScoreRequest(BaseModel):
    repo: str
    pr: int
    sha: Optional[str] = None

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

def get_pr_details(repo_full_name: str, pr_number: int) -> Dict:
    """Fetch PR details (title, author, labels) using GitHub API."""
    if not GITHUB_TOKEN:
        return {}

    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        print(f"Failed to fetch PR details: {resp.status_code}")
    except Exception as e:
        print(f"Error fetching PR details: {e}")
        
    return {}

def post_pr_comment(repo_full_name: str, pr_number: int, body: str):
    """Post a comment to the PR."""
    if not GITHUB_TOKEN:
        return

    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        requests.post(url, json={"body": body}, headers=headers)
        print(f"Posted comment to PR #{pr_number}")
    except Exception as e:
        print(f"Failed to post comment: {e}")

def create_check_run(repo_full_name: str, head_sha: str, score: int, risk_level: str, reasons: list):
    """Create a GitHub Check Run."""
    if not GITHUB_TOKEN:
        print("Warning: No GITHUB_TOKEN, skipping check run creation.")
        return

    url = f"https://api.github.com/repos/{repo_full_name}/check-runs"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    conclusion = "failure" if risk_level == "HIGH" else "success"
    title = f"RiskBot CI: {risk_level} risk (Score: {score})"
    summary = "Risk analysis completed.\n\n### Reasons\n" + "\n".join(f"- {r}" for r in reasons)
    
    payload = {
        "name": "RiskBot CI",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary
        }
    }
    
    if RISK_WEBHOOK_URL:
        payload["details_url"] = RISK_WEBHOOK_URL
    
    try:
        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code not in [200, 201]:
             print(f"Failed to create check run: {resp.status_code} - {resp.text}")
        else:
             print(f"Created check run: {title}")
    except Exception as e:
        print(f"Error creating check run: {e}")

def get_repo_config(repo_full_name: str, default_branch: str = "main") -> Dict:
    """Fetch and parse riskbot_config.yml from the repo."""
    if not GITHUB_TOKEN: 
        return {}
        
    url = f"https://api.github.com/repos/{repo_full_name}/contents/riskbot_config.yml?ref={default_branch}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            content = resp.json().get("content", "")
            if content:
                decoded = base64.b64decode(content).decode("utf-8")
                return yaml.safe_load(decoded) or {}
    except Exception as e:
        print(f"Config fetch failed: {e}")
        
    return {}

@app.post("/ci/score")
def ci_score(payload: CIScoreRequest):
    """
    CI Endpoint: Returns risk score and level for a given PR.
    Used by GitHub Actions to block merges.
    """
    repo_full_name = payload.repo
    pr_number = payload.pr
    print(f"CI Analysis Request: {repo_full_name} #{pr_number}")
    
    # 1. Fetch Data
    pr_data = get_pr_details(repo_full_name, pr_number)
    filenames, diff_stats = get_pr_files(repo_full_name, pr_number)
    
    if not pr_data:
         # Fallback if API fails
         print("Warning: Could not fetch PR details")
         
    # 2. Construct Features
    features = {
        "diff": diff_stats,
        "files": filenames,
        "churn": {"hotspots": []},
        "paths": [f for f in filenames if "config" in f or "auth" in f],
        "tests": any("test" in f for f in filenames),
        "metadata": {
            "title": pr_data.get("title", ""),
            "author": pr_data.get("user", {}).get("login", "unknown"),
            "state": pr_data.get("state", "open"),
            "merged": pr_data.get("merged", False)
        }
    }
    
    # 3. Calculate Score
    score_data = calculate_score(features)
    
    # 4. Config & Thresholds (Reuse logic)
    config = get_repo_config(repo_full_name, pr_data.get("base", {}).get("ref", "main"))
    high_threshold = config.get("high_threshold", 75)
    
    bypass_users = config.get("bypass_users", [])
    bypass_labels = config.get("bypass_labels", [])
    pr_labels = [l["name"] for l in pr_data.get("labels", [])]
    author = features["metadata"]["author"]
    
    is_bypassed = False
    
    if author in bypass_users:
        is_bypassed = True
    if any(l in bypass_labels for l in pr_labels):
        is_bypassed = True
        
    risk_level = "HIGH" if score_data["score"] >= high_threshold else "LOW"
    
    # JSON Response for CI
    # If bypassed, we report LOW risk or specific status to let CI pass
    if is_bypassed and risk_level == "HIGH":
        risk_level = "BYPASSED" # CI script should treat this as passing
        
    return {
        "score": score_data["score"],
        "level": risk_level,
        "reasons": score_data["reasons"]
    }

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
    # DO NOT strip dash here, we need exact name for API calls
    # if repo_full_name:
    #    repo_full_name = repo_full_name.strip("-")
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
    
    # --- 4. Repo Config & Bypass Logic ---
    default_branch = repo.get("default_branch", "main")
    config = get_repo_config(repo_full_name, default_branch)
    
    # Thresholds
    high_threshold = config.get("high_threshold", 75)
    
    # Bypass logic
    bypass_users = config.get("bypass_users", [])
    bypass_labels = config.get("bypass_labels", [])
    pr_labels = [l["name"] for l in pr.get("labels", [])]
    
    is_bypassed = False
    bypass_reason = ""
    
    if author in bypass_users:
        is_bypassed = True
        bypass_reason = f"Author '{author}' is on bypass list."
        
    if any(l in bypass_labels for l in pr_labels):
        is_bypassed = True
        bypass_reason = f"PR has bypass label."
    
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
    
    # Apply Configurable Thresholds
    score = score_data["score"]
    risk_level = "HIGH" if score >= high_threshold else "LOW" # Simplifying for now
    
    if is_bypassed and risk_level == "HIGH":
        risk_level = "BYPASSED"
        score_data["reasons"].append(f"**BYPASSED**: {bypass_reason}")
    else:
        # Override the calculated level if needed based on new threshold
        score_data["risk_level"] = risk_level

    # Save to DB
    # Use clean repo name for storage/analytics as requested
    repo_clean = repo_full_name.strip("-") if repo_full_name else repo_full_name
    save_run(
        repo=repo_clean,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        score_data=score_data,
        features=features
    )

    # Post Comment (Feedback Loop)
    comment_body = (
        f"## 🛡️ RiskBot Analysis\n\n"
        f"**Risk Score**: {score_data.get('score')} / 100 ({score_data.get('risk_level')})\n\n"
        f"### Reasons\n"
        + "\n".join(f"- {r}" for r in score_data.get("reasons", []))
    )
    # Use original repo_full_name for API calls
    post_pr_comment(repo_full_name, pr_number, comment_body)
    
    # Create Check Run (Enforcement)
    create_check_run(repo_full_name, head_sha, score_data["score"], score_data["risk_level"], score_data["reasons"])
    
    return {
        "status": "processed",
        "risk_score": score_data.get("score"),
        "risk_level": score_data.get("risk_level")
    }

@app.get("/")
def health_check():
    return {"status": "ok", "service": "RiskBot Webhook Listener"}
