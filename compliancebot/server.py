from compliancebot.features.feature_store import FeatureStore
from compliancebot.storage.sqlite import save_run
from compliancebot.scoring.calibration import Calibrator
from compliancebot.scoring.risk_score import RiskScorer
from compliancebot.ingestion.pr_parser import PRParser
from compliancebot.config import (
    GITHUB_TOKEN, WEBHOOK_URL,
    SEVERITY_THRESHOLD_HIGH
)
import hmac
import hashlib
import json
import os
import requests
import yaml
import base64
import git
from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv

# Load env vars
load_dotenv()


# Initialize App
app = FastAPI(title="ComplianceBot Webhook Listener")


class CIScoreRequest(BaseModel):
    repo: str
    pr: int
    sha: Optional[str] = None


# --- Config ---
# Use user's preferred default
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # For API calls


def get_pr_files(repo_full_name: str, pr_number: int):
    """Fetch files changed in PR using GitHub API."""
    if not GITHUB_TOKEN:
        print("Warning: No GITHUB_TOKEN, cannot fetch file details.")
        return [], {"files_changed": 0, "loc_added": 0, "loc_deleted": 0, "total_churn": 0}, {}

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
        total_churn = added + deleted

        per_file = {
            f['filename']: f.get('additions', 0) + f.get('deletions', 0)
            for f in files_data
        }

        return filenames, {
            "files_changed": len(files_data),
            "loc_added": added,
            "loc_deleted": deleted,
            "total_churn": total_churn
        }, per_file
    except Exception as e:
        print(f"Error fetching files: {e}")
        return [], {}, {}


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


def create_check_run(repo_full_name: str, head_sha: str, score: int, risk_level: str, reasons: list, evidence: list = None):
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
    title = f"ComplianceBot CI: {risk_level} severity (Score: {score})"

    summary = "Risk analysis completed.\n\n### Reasons\n" + \
        "\n".join(f"- {r}" for r in reasons)

    if evidence:
        summary += "\n\n### Evidence\n" + "\n".join(f"- {e}" for e in evidence)

    payload = {
        "name": "ComplianceBot CI",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary
        }
    }

    if WEBHOOK_URL:
        payload["details_url"] = WEBHOOK_URL

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
    filenames, diff_stats, per_file_churn = get_pr_files(
        repo_full_name, pr_number)

    if not pr_data:
        # Fallback if API fails
        print("Warning: Could not fetch PR details")

    # 2. Extract Features (Phase 6 refined)
    raw_signals = {
        "repo_slug": repo_full_name,
        "entity_type": "pr",
        "entity_id": str(pr_number),
        "timestamp": pr_data.get("created_at", "unknown"),
        "files_changed": filenames,
        "lines_added": diff_stats.get("loc_added", 0),
        "lines_deleted": diff_stats.get("loc_deleted", 0),
        "total_churn": diff_stats.get("total_churn", 0),
        "per_file_churn": per_file_churn,
        "touched_services": [],  # Placeholder
        "linked_issue_ids": [],  # CI endpoint might skip issue parsing or add it if needed
        "author": pr_data.get("user", {}).get("login"),
        "branch": pr_data.get("head", {}).get("ref")
    }

    # 3. Feature Engineering
    # Get Config used for RiskScorer/FeatureStore
    config = get_repo_config(
        repo_full_name, pr_data.get("base", {}).get("ref", "main"))

    feature_store = FeatureStore(config)
    features, feature_explanations = feature_store.build_features(raw_signals)

    # 4. Calculate Score (V2 Engine)
    scorer = RiskScorer(config)
    calibrator = Calibrator()  # Uses default curve if no DB

    score_result = scorer.calculate_score(
        features, evidence=feature_explanations)
    risk_score = score_result["risk_score"]
    risk_level = score_result["risk_level"]
    risk_prob = score_result["risk_prob"]
    reasons = score_result["reasons"]
    decision = score_result["decision"]

    return {
        "score": risk_score,
        "level": risk_level,
        "probability": risk_prob,
        "decision": decision,
        "reasons": reasons,
        "model_version": score_result.get("model_version"),
        "feature_version": score_result.get("feature_version")
    }


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
):
    payload = await request.body()

    # Handle GitHub ping FIRST
    if x_github_event == "ping":
        return {"msg": "pong"}

    # Verify signature
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
    # repo_full_name = repo_full_name.strip("-")
    pr_number = pr.get("number")

    if not repo_full_name or not pr_number:
        return {"msg": "Missing repo or pr_number"}

    print(f"Processing PR #{pr_number} for {repo_full_name} ({action})")

    # Fetch Extra Features (Diff Stats)
    filenames, diff_stats, per_file_churn = get_pr_files(
        repo_full_name, pr_number)

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

    # Construct Raw Signals for FeatureStore
    raw_signals = {
        "repo_slug": repo_full_name,
        "entity_type": "pr",
        "entity_id": str(pr_number),
        "timestamp": pr.get("created_at"),
        "files_changed": filenames,
        "lines_added": diff_stats.get("loc_added", 0),
        "lines_deleted": diff_stats.get("loc_deleted", 0),
        "total_churn": diff_stats.get("total_churn", 0),
        "per_file_churn": per_file_churn,
        "touched_services": [],
        "linked_issue_ids": [],  # Populated below
        "author": author,
        "branch": pr.get("head", {}).get("ref")
    }

    # --- 5. Evidence Collection (Phase 4) ---
    evidence = []

    # Instantiate Provider
    from compliancebot.ingestion.providers.github_provider import GitHubProvider
    # Minimal config for provider
    provider_config = {"github": {"repo": repo_full_name, "cache_ttl": 3600}}
    provider = GitHubProvider(provider_config)

    # Parse Links
    import re
    pr_body = pr.get("body") or ""
    # Matches #123, owner/repo#123
    # Use simple #123 for MVP within same repo
    linked_issues = re.findall(r"#(\d+)", pr_body)

    # Fetch Labels for Linked Issues
    if linked_issues:
        print(f"Checking linked issues: {linked_issues}")
        for issue_num in linked_issues:
            labels = provider.fetch_issue_labels(issue_num)
            risky_labels = config.get("labels", {}).get(
                "risky_any_of", ["bug", "incident", "sev1"])

            found_risky = [l for l in labels if l in risky_labels]
            if found_risky:
                evidence.append(
                    f" Linked Issue #{issue_num} labeled **{' '.join(found_risky)}** (High Confidence)")
            # Boost core features? Or just rely on evidence display?
            # Ideally, this should impact the score. For V1, we just display it.

    # Check for Revert
    if "revert" in title.lower():
        evidence.append("PR Title indicates a **Revert** operation.")

    # Update Raw Signals with linked issues
    raw_signals["linked_issue_ids"] = linked_issues

    # Calculate Score & Evaluate Policies
    from compliancebot.engine import ComplianceEngine
    engine = ComplianceEngine(config)
    run_result = engine.evaluate(raw_signals)

    # Map to legacy score_data format for save_run/comments (or update those too)
    # We'll construct a hybrid object to satisfy existing helpers
    score_data = {
        "risk_score": run_result.metadata.get("core_risk_score", 0),
        "risk_level": run_result.metadata.get("core_risk_level", "UNKNOWN"),
        "decision": run_result.overall_status,  # BLOCK/WARN/COMPLIANT
        "reasons": [],
        "evidence": []
    }

    # Extract reasons/evidence from Policy Results
    for p in run_result.results:
        if p.status in ["BLOCK", "WARN"]:
            for v in p.violations:
                score_data["reasons"].append(f"[{p.policy_id}] {v}")

    # Save to DB
    # Use clean repo name for storage/analytics as requested
    repo_clean = repo_full_name.strip(
        "-") if repo_full_name else repo_full_name

    # Note: save_run expects specific schema. We might keep using it or update it.
    # For now, we pass the mapped score_data.
    features = run_result.metadata.get("raw_features", {})
    save_run(
        repo=repo_clean,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        score_data=score_data,
        features=features
    )

    # Post Comment (Feedback Loop)
    emoji = "COMPLIANT" if run_result.overall_status == "COMPLIANT" else "BLOCK" if run_result.overall_status == "BLOCK" else "WARN"

    comment_body = (
        f"## {emoji} Compliance Check — {run_result.overall_status}\n\n"
        f"**Severity**: {score_data['risk_level']} ({score_data['risk_score']})\n"
        f"**Control Result**: {run_result.overall_status}\n\n"
        f"### Violations\n"
        + ("\n".join(f"- {r}" for r in score_data.get("reasons", []))
           if score_data["reasons"] else "_No policy violations found._")
    )
    # Use original repo_full_name for API calls
    post_pr_comment(repo_full_name, pr_number, comment_body)

    # Create Check Run (Enforcement)
    # Update title format as requested
    check_title = f"Compliance Check — {run_result.overall_status}"
    # WARN is success? or neutral? GitHub only has success/failure/neutral/cancelled...
    conclusion = "failure" if run_result.overall_status == "BLOCK" else "success"
    # Usually WARN -> success with annotation, or neutral. Let's stick to success for non-blocking.

    create_check_run(
        repo_full_name,
        head_sha,
        score_data["risk_score"],
        score_data["risk_level"],
        score_data["reasons"],
        evidence=evidence
    )

    return {
        "status": "processed",
        "result": run_result.overall_status,
        "risk_score": score_data["risk_score"],
        "severity": score_data["risk_level"]
    }


@app.get("/")
def health_check():
    return {"status": "ok", "service": "RiskBot Webhook Listener"}
