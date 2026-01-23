import argparse
import json
import os
import requests
import sys

def publish_check(result_path: str, repo: str, sha: str, token: str):
    """
    Publish a GitHub Check Run from a JSON result file.
    """
    if not os.path.exists(result_path):
        print(f"Result file not found: {result_path}")
        return

    with open(result_path, "r") as f:
        data = json.load(f)

    score = data.get("risk_score", 0)
    level = data.get("risk_level", "UNKNOWN")
    reasons = data.get("reasons", [])
    evidence = data.get("evidence", [])
    decision = data.get("decision", "PASS") # PASS/WARN/FAIL

    # Determine conclusion based on decision
    # If decision is FAIL, we mark failure.
    # WARN is neutral or success with warning? Usually neutral or failure depending on policy.
    # Check Runs only support: success, failure, neutral, cancelled, skipped, timed_out, action_required
    conclusion = "success"
    if decision == "FAIL":
        conclusion = "failure"
    elif decision == "WARN":
        conclusion = "neutral" 

    title = f"RiskBot: {decision} ({score}/100)"
    summary = f"**Risk Level**: {level}\n**Decision**: {decision}\n\n"
    
    # Add review priority if available
    if "priority" in data:
        priority = data["priority"]
        priority_label = data.get("priority_label", "Normal")
        summary += f"🔍 **Review Priority**: {priority} — {priority_label}\n\n"
    
    summary += "### Primary Reasons\n" + \
              "\n".join(f"- {r}" for r in reasons)
              
    if evidence:
        summary += "\n\n### Evidence\n" + "\n".join(f"- {e}" for e in evidence)

    # API Call
    url = f"https://api.github.com/repos/{repo}/check-runs"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    payload = {
        "name": "RiskBot / Risk Score",  # Stable name for branch protection
        "head_sha": sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary
        }
    }
    
    print(f"Publishing Check Run to {repo} @ {sha}...")
    try:
        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code in [200, 201]:
            print("Check Run published.")
        else:
            print(f"Failed to publish: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"Error publishing check: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", required=True, help="Path to risk_result.json")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--sha", required=True, help="Commit SHA")
    parser.add_argument("--token", required=True, help="GitHub Token")
    
    args = parser.parse_args()
    publish_check(args.result, args.repo, args.sha, args.token)
