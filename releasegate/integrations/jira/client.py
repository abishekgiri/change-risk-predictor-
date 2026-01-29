import os
import requests
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime

class JiraClient:
    def __init__(self):
        self.base_url = os.getenv("JIRA_BASE_URL", "").rstrip("/")
        self.email = os.getenv("JIRA_EMAIL", "")
        self.token = os.getenv("JIRA_API_TOKEN", "")
        self.auth = (self.email, self.token)
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def check_permissions(self) -> bool:
        """Health check: verifies credentials and basic read access."""
        if not all([self.base_url, self.email, self.token]):
            return False
        try:
            # myself endpoint is lightweight
            resp = requests.get(self._url("/rest/api/3/myself"), auth=self.auth, headers=self.headers, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def get_issue_details(self, issue_key: str) -> Dict[str, Any]:
        """Fetch basic issue details (Status, Project, Type)."""
        resp = requests.get(
            self._url(f"/rest/api/3/issue/{issue_key}"),
            params={"fields": "status,project,issuetype"},
            auth=self.auth,
            headers=self.headers,
            timeout=10
        )
        resp.raise_for_status()
        return resp.json()

    def get_dev_status(self, issue_id: str) -> Dict[str, Any]:
        """
        Fetch linked development information (PRs).
        Note: Requires 'issue_id' (numeric ID), not key.
        """
        # This is an internal API, but widely used. Alternatively use GraphQL or properties.
        # Fallback safety: If this fails, we return empty structure to trigger fallback logic in caller.
        try:
            resp = requests.get(
                self._url("/rest/dev-status/1.0/issue/detail"),
                params={
                    "issueId": issue_id,
                    "applicationType": "github", # or gitlab, or omit to get all
                    "dataType": "pullrequest"
                },
                auth=self.auth,
                headers=self.headers,
                timeout=5
            )
            if resp.status_code == 200:
                return resp.json()
            return {}
        except Exception:
            return {}

    def post_comment_deduped(self, issue_key: str, body: str, dedup_hash: str) -> bool:
        """
        Post a comment only if the last ReleaseGate comment doesn't match the dedup_hash.
        Returns True if posted, False if skipped.
        """
        # 1. Fetch recent comments (limit 5 to save bandwidth)
        try:
            resp = requests.get(
                self._url(f"/rest/api/3/issue/{issue_key}/comment"),
                params={"orderBy": "-created", "maxResults": 5},
                auth=self.auth,
                headers=self.headers
            )
            if resp.status_code == 200:
                comments = resp.json().get("comments", [])
                for c in comments:
                    # Check if it looks like a ReleaseGate comment and matches hash
                    content_str = str(c.get("body", "")) 
                    # Note: Jira V3 uses ADF (Atlassian Document Format). 
                    # Parsing ADF text is complex. We'll simplify by checking a property if possible,
                    # or just implementing a simpler "always post if blocked" for now, 
                    # but User asked for dedup.
                    # Strategy: If the body contains our unique hash (hidden or footer), we skip.
                    if dedup_hash in content_str:
                        return False
        except Exception:
            pass # Fail open on dedup check error (safe to double post rather than silence)

        # 2. Post Comment (ADF Format)
        adf_body = {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": body}
                    ]
                },
                {
                   "type": "paragraph",
                   "content": [
                       {"type": "text", "text": f"\nRef: {dedup_hash}", "marks": [{"type": "code"}]}
                   ] 
                }
            ]
        }
        
        try:
            requests.post(
                self._url(f"/rest/api/3/issue/{issue_key}/comment"),
                json={"body": adf_body},
                auth=self.auth,
                headers=self.headers
            )
            return True
        except Exception:
            return False

