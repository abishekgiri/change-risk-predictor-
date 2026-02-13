import json
import sqlite3
import os
from typing import List, Dict, Any
from datetime import datetime, timedelta
from github import Github, Auth
from releasegate.config import GITHUB_TOKEN, DB_PATH
from releasegate.ingestion.providers.base import GitProvider
from releasegate.storage.schema import init_db
from releasegate.signals.approvals.types import Review

class GitHubProvider(GitProvider):
    """
    Implementation of GitProvider for GitHub (Public or Private).
    Uses PyGithub and SQLite Caching.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.repo_name = config.get("github", {}).get("repo")
        self.cache_ttl = config.get("github", {}).get("cache_ttl", 3600)
        init_db()
        self.client = self._init_client()

    def _init_client(self):
        """
        Initialize GitHub Client using App Auth (Preferred) or PAT (Fallback).
        """
        app_id = os.getenv("GITHUB_APP_ID")
        private_key = os.getenv("GITHUB_APP_PRIVATE_KEY")
        installation_id = os.getenv("GITHUB_INSTALLATION_ID")
        
        # Option B2.1: GitHub App Auth
        if app_id and private_key and installation_id:
            try:
                token = self._get_installation_token(app_id, private_key, installation_id)
                print("Using GitHub App Authentication")
                return Github(auth=Auth.Token(token))
            except Exception as e:
                print(f"App Auth Failed: {e}. Falling back to Token/Public.")
        
        # Option B2.2: PAT
        if GITHUB_TOKEN:
            return Github(auth=Auth.Token(GITHUB_TOKEN))
        
        print("Warning: No Auth found. Using unauthenticated client (strict rate limits).")
        return Github()

    def _get_installation_token(self, app_id, private_key, installation_id):
        import jwt
        import time
        import requests
        
        # 1. Create JWT
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 600, # 10 min
            "iss": app_id
        }
        encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")
        
        # 2. Exchange for Installation Token
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {encoded_jwt}",
            "Accept": "application/vnd.github.v3+json"
        }
        resp = requests.post(url, headers=headers)
        resp.raise_for_status()
        return resp.json()["token"]

    def _get_cache(self, key: str) -> Dict:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT response_json, fetched_at FROM github_cache WHERE cache_key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            data, fetched_at = row
            fetched_dt = datetime.fromisoformat(fetched_at)
            if datetime.utcnow() - fetched_dt < timedelta(seconds=self.cache_ttl):
                return json.loads(data)
        return None

    def _set_cache(self, key: str, data: Dict):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
        INSERT OR REPLACE INTO github_cache (cache_key, response_json, fetched_at)
        VALUES (?, ?, ?)
        """, (key, json.dumps(data), datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

    def fetch_issue_labels(self, issue_ref: str) -> List[str]:
        """
        Ref should be an issue number (str or int).
        """
        if not self.client or not self.repo_name:
            return []
        
        # Clean ref "#123" -> 123
        try:
            issue_num = int(str(issue_ref).replace("#", ""))
        except ValueError:
            return []
        
        cache_key = f"github:{self.repo_name}:issue:{issue_num}"
        data = self._get_cache(cache_key)
        
        if not data:
            try:
                repo = self.client.get_repo(self.repo_name)
                issue = repo.get_issue(issue_num)
                data = {
                    "labels": [l.name for l in issue.get_labels()],
                    "state": issue.state,
                    "title": issue.title,
                    "is_pr": issue.pull_request is not None
                }
                self._set_cache(cache_key, data)
            except Exception as e:
                print(f"Error fetching GitHub issue {issue_num}: {e}")
                return []
        
        return data.get("labels", [])

    def fetch_pr_details(self, pr_number: int) -> Dict[str, Any]:
        # Reuse same logic, PRs are issues
        labels = self.fetch_issue_labels(str(pr_number))
        # We could return more here if needed, but labels are primary for now
        return {"labels": labels}

    def get_reviews(self, repo_full_name: str, pr_number: int):
        """
        Fetch PR reviews and return normalized Review objects.
        Returns None on error or if client/repo is not configured.
        """
        if not self.client or not repo_full_name:
            return None

        try:
            repo = self.client.get_repo(repo_full_name)
            pr = repo.get_pull(int(pr_number))
            reviews = []
            for r in pr.get_reviews():
                reviews.append(Review(
                    reviewer=r.user.login if r.user else "unknown",
                    state=r.state,
                    submitted_at=r.submitted_at,
                    commit_id=getattr(r, "commit_id", "") or ""
                ))
            return reviews
        except Exception as e:
            print(f"Error fetching GitHub reviews for PR {pr_number}: {e}")
            return None

    def get_pr_author(self, repo_full_name: str, pr_number: int):
        """
        Fetch PR author login.
        """
        if not self.client or not repo_full_name:
            return None
        try:
            repo = self.client.get_repo(repo_full_name)
            pr = repo.get_pull(int(pr_number))
            return pr.user.login if pr.user else None
        except Exception:
            return None

    def get_team_members(self, team_slug: str):
        """
        Fetch organization team members by slug.
        team_slug accepted as "org/team" or "team".
        """
        if not self.client:
            return None
        raw = str(team_slug or "").strip()
        if not raw:
            return None
        try:
            if "/" in raw:
                org_name, slug = raw.split("/", 1)
            else:
                # Without org context, team lookup is ambiguous.
                return None
            org = self.client.get_organization(org_name)
            team = org.get_team_by_slug(slug)
            return [m.login for m in team.get_members() if getattr(m, "login", None)]
        except Exception:
            return None

    def get_file_content(self, repo_full_name: str, path: str, ref: str = None):
        """
        Fetch file content from GitHub. Returns decoded text or None.
        """
        if not self.client or not repo_full_name:
            return None
        try:
            repo = self.client.get_repo(repo_full_name)
            contents = repo.get_contents(path, ref=ref) if ref else repo.get_contents(path)
            if isinstance(contents, list):
                return None
            data = contents.decoded_content
            return data.decode("utf-8", errors="replace") if data is not None else None
        except Exception as e:
            print(f"Error fetching file content {path}: {e}")
            return None
