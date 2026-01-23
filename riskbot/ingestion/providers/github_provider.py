import json
import sqlite3
import os
from typing import List, Dict, Any
from datetime import datetime, timedelta
from github import Github
from riskbot.config import GITHUB_TOKEN, RISK_DB_PATH
from riskbot.ingestion.providers.base import GitProvider

class GitHubProvider(GitProvider):
    """
    Implementation of GitProvider for GitHub (Public or Private).
    Uses PyGithub and SQLite Caching.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.repo_name = config.get("github", {}).get("repo")
        self.cache_ttl = config.get("github", {}).get("cache_ttl", 3600)
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
                print("✅ Using GitHub App Authentication")
                return Github(token)
            except Exception as e:
                print(f"⚠️ App Auth Failed: {e}. Falling back to Token/Public.")
        
        # Option B2.2: PAT
        if GITHUB_TOKEN:
            return Github(GITHUB_TOKEN)
            
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
        conn = sqlite3.connect(RISK_DB_PATH)
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
        conn = sqlite3.connect(RISK_DB_PATH)
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
