import os
from typing import Optional

try:
    from github import Github, Auth
except ImportError:
    Github = None

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore[assignment]


def _github_token() -> Optional[str]:
    return os.getenv("GITHUB_TOKEN")


def post_comment(repo_name: str, pr_number: int, body: str):
    """Post a comment to a GitHub PR."""
    token = _github_token()
    if not token:
        print("Warning: GITHUB_TOKEN not set, skipping comment.")
        return

    if not Github:
        print("Warning: PyGithub not installed, skipping comment.")
        return

    auth = Auth.Token(token)
    g = Github(auth=auth)
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    pr.create_issue_comment(body)
    print(f"Posted comment to PR #{pr_number}")


def set_commit_status(
    repo_name: str,
    sha: str,
    state: str,
    description: str,
    context: str = "releasegate/fabric",
    target_url: Optional[str] = None,
) -> bool:
    """Post a commit status to GitHub (POST /repos/{owner}/{repo}/statuses/{sha}).

    state must be one of: "pending", "success", "failure", "error"
    Returns True on success, False if skipped or failed.
    """
    token = _github_token()
    if not token:
        print("Warning: GITHUB_TOKEN not set, skipping commit status.")
        return False

    if not sha or len(sha) < 7:
        print(f"Warning: invalid SHA '{sha}', skipping commit status.")
        return False

    valid_states = {"pending", "success", "failure", "error"}
    if state not in valid_states:
        print(f"Warning: invalid state '{state}', must be one of {valid_states}.")
        return False

    payload: dict = {
        "state": state,
        "description": description[:140],  # GitHub limits description to 140 chars
        "context": context,
    }
    if target_url:
        payload["target_url"] = target_url

    url = f"https://api.github.com/repos/{repo_name}/statuses/{sha}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if _requests is not None:
        try:
            resp = _requests.post(url, json=payload, headers=headers, timeout=10)
            if resp.status_code == 201:
                return True
            print(f"Warning: GitHub commit status API returned {resp.status_code}: {resp.text[:200]}")
            return False
        except Exception as exc:
            print(f"Warning: GitHub commit status request failed: {exc}")
            return False

    # Fallback: use urllib (stdlib only)
    import json
    import urllib.request
    import urllib.error

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 201
    except urllib.error.HTTPError as exc:
        print(f"Warning: GitHub commit status API returned {exc.code}")
        return False
    except Exception as exc:
        print(f"Warning: GitHub commit status request failed: {exc}")
        return False
