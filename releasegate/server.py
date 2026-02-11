from releasegate.storage.sqlite import save_run
from releasegate.config import (
    GITHUB_TOKEN, WEBHOOK_URL
)
from releasegate.integrations.github_risk import (
    PRRiskInput,
    build_issue_risk_property,
    classify_pr_risk,
    extract_jira_issue_keys,
    score_for_risk_level,
)
import hmac
import hashlib
import json
import os
import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
import csv
import io
from pydantic import BaseModel
from typing import Optional, Dict, Any
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


def get_pr_metrics(repo_full_name: str, pr_number: int) -> PRRiskInput:
    """
    Fetch minimal PR counters from GitHub (no diff/file content).
    """
    pr_data = get_pr_details(repo_full_name, pr_number)
    return PRRiskInput(
        changed_files=int(pr_data.get("changed_files", 0) or 0),
        additions=int(pr_data.get("additions", 0) or 0),
        deletions=int(pr_data.get("deletions", 0) or 0),
    )


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


@app.post("/ci/score")
def ci_score(payload: CIScoreRequest):
    """
    CI Endpoint: Returns metadata-only risk classification for a PR.
    """
    repo_full_name = payload.repo
    pr_number = payload.pr
    print(f"CI Analysis Request: {repo_full_name} #{pr_number}")

    pr_data = get_pr_details(repo_full_name, pr_number)
    metrics = PRRiskInput(
        changed_files=int(pr_data.get("changed_files", 0) or 0),
        additions=int(pr_data.get("additions", 0) or 0),
        deletions=int(pr_data.get("deletions", 0) or 0),
    )

    risk_level = classify_pr_risk(metrics)
    risk_score = score_for_risk_level(risk_level)
    decision = "BLOCK" if risk_level == "HIGH" else "WARN" if risk_level == "MEDIUM" else "PASS"

    return {
        "score": risk_score,
        "level": risk_level,
        "decision": decision,
        "metrics": {
            "changed_files_count": metrics.changed_files,
            "additions": metrics.additions,
            "deletions": metrics.deletions,
            "total_churn": metrics.total_churn,
        },
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

    base_sha = pr.get("base", {}).get("sha", "unknown")
    head_sha = pr.get("head", {}).get("sha", "unknown")
    title = pr.get("title", "")
    metrics = PRRiskInput(
        changed_files=int(pr.get("changed_files", 0) or 0),
        additions=int(pr.get("additions", 0) or 0),
        deletions=int(pr.get("deletions", 0) or 0),
    )
    if metrics.changed_files == 0 and metrics.additions == 0 and metrics.deletions == 0:
        metrics = get_pr_metrics(repo_full_name, int(pr_number))

    risk_level = classify_pr_risk(metrics)
    risk_score = score_for_risk_level(risk_level)
    decision = "BLOCK" if risk_level == "HIGH" else "WARN" if risk_level == "MEDIUM" else "PASS"

    issue_keys = sorted(extract_jira_issue_keys(title, pr.get("body") or ""))
    attached_issue_keys = []
    if issue_keys:
        try:
            from releasegate.integrations.jira.client import JiraClient

            client = JiraClient()
            payload = build_issue_risk_property(
                repo=repo_full_name,
                pr_number=int(pr_number),
                risk_level=risk_level,
                metrics=metrics,
            )
            for issue_key in issue_keys:
                if client.set_issue_property(issue_key, "releasegate_risk", payload):
                    attached_issue_keys.append(issue_key)
        except Exception as e:
            print(f"Warning: Jira risk attach failed: {e}")

    score_data = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "decision": decision,
        "reasons": [f"Heuristic classification from GitHub metadata: {risk_level}"],
    }
    features = {
        "source": "github_metadata",
        "changed_files_count": metrics.changed_files,
        "additions": metrics.additions,
        "deletions": metrics.deletions,
        "total_churn": metrics.total_churn,
        "attached_issue_keys": attached_issue_keys,
    }

    save_run(
        repo=repo_full_name,
        pr_number=int(pr_number),
        base_sha=base_sha,
        head_sha=head_sha,
        score_data=score_data,
        features=features,
    )

    return {
        "status": "processed",
        "result": decision,
        "risk_score": risk_score,
        "severity": risk_level,
        "attached_issue_keys": attached_issue_keys,
        "metrics": features,
    }


@app.get("/")
def health_check():
    return {"status": "ok", "service": "RiskBot Webhook Listener"}


def _derive_reason_code(decision: str, message: str, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    msg = (message or "").lower()
    if "override" in msg:
        return "OVERRIDE_APPLIED"
    if "missing issue property `releasegate_risk`" in msg or "missing risk" in msg:
        return "MISSING_RISK_METADATA"
    if "no policies configured" in msg:
        return "NO_POLICIES_MAPPED"
    if "system error" in msg:
        return "SYSTEM_ERROR"
    if decision == "BLOCKED":
        return "POLICY_BLOCKED"
    if decision == "CONDITIONAL":
        return "POLICY_CONDITIONAL"
    if decision == "SKIPPED":
        return "POLICY_SKIPPED"
    return "POLICY_ALLOWED"


def _soc2_records(
    rows: list,
    overrides: Optional[list] = None,
    chain_verified: Optional[bool] = None,
) -> list:
    override_map = {}
    if overrides:
        for ov in overrides:
            d_id = ov.get("decision_id")
            if d_id and d_id not in override_map:
                override_map[d_id] = ov

    records = []
    for r in rows:
        full = {}
        raw_full = r.get("full_decision_json")
        if raw_full:
            try:
                full = json.loads(raw_full) if isinstance(raw_full, str) else (raw_full or {})
            except Exception:
                full = {}

        decision = full.get("release_status") or r.get("release_status") or "UNKNOWN"
        message = full.get("message") or ""
        explicit_reason = full.get("reason_code")
        ov = override_map.get(r.get("decision_id"))

        records.append({
            "decision_id": r.get("decision_id"),
            "decision": decision,
            "reason_code": _derive_reason_code(decision, message, explicit_reason),
            "human_message": message,
            "actor": full.get("actor_id") or (ov.get("actor") if ov else None),
            "policy_version": full.get("policy_bundle_hash") or r.get("policy_bundle_hash"),
            "inputs_present": full.get("inputs_present") or {},
            "override_id": ov.get("override_id") if ov else None,
            "chain_verified": chain_verified if chain_verified is not None else None,
            "repo": r.get("repo"),
            "pr_number": r.get("pr_number"),
            "created_at": r.get("created_at"),
        })
    return records


@app.get("/audit/export")
def audit_export(
    repo: str,
    format: str = "json",
    limit: int = 200,
    status: Optional[str] = None,
    pr: Optional[int] = None,
    include_overrides: bool = False,
    verify_chain: bool = False,
    contract: str = "soc2_v1",
):
    """
    Export audit decisions in JSON or CSV.
    """
    from releasegate.audit.reader import AuditReader
    rows = AuditReader.list_decisions(repo=repo, limit=limit, status=status, pr=pr)
    payload = {"decisions": rows}
    overrides = []
    chain_result = None

    include_override_data = include_overrides or contract == "soc2_v1"

    if include_override_data:
        try:
            from releasegate.audit.overrides import list_overrides, verify_override_chain
            overrides = list_overrides(repo=repo, limit=limit, pr=pr)
            payload["overrides"] = overrides if include_overrides else []
            if verify_chain:
                chain_result = verify_override_chain(repo=repo, pr=pr)
                payload["override_chain"] = chain_result
        except Exception:
            payload["overrides"] = []

    export_rows = rows
    if contract == "soc2_v1":
        chain_flag = bool(chain_result.get("valid")) if (verify_chain and chain_result is not None) else (False if verify_chain else None)
        export_rows = _soc2_records(rows, overrides=overrides, chain_verified=chain_flag)
        payload = {
            "contract": "soc2_v1",
            "repo": repo,
            "records": export_rows,
        }
        if verify_chain:
            payload["override_chain"] = chain_result if chain_result is not None else {"valid": False, "checked": 0}

    if format.lower() == "csv":
        if not export_rows:
            return PlainTextResponse("", media_type="text/csv")
        output = io.StringIO()
        fieldnames = list(export_rows[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for r in export_rows:
            writer.writerow(r)
        return PlainTextResponse(output.getvalue(), media_type="text/csv")

    return payload
