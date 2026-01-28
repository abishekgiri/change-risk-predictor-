import requests
import json
import sqlite3
import re
from typing import List, Dict, Any
from datetime import datetime, timedelta
from compliancebot.config import DB_PATH
from compliancebot.ingestion.providers.base import GitProvider

class GitLabProvider(GitProvider):
    """
    Implementation of GitProvider for GitLab (Cloud or Self-Hosted).
    Uses 'requests' directly to avoid heavy dependencies like python-gitlab.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.gitlab_config = config.get("gitlab", {})
        self.base_url = self.gitlab_config.get("url", "https://gitlab.com").rstrip("/")
        self.token = self.gitlab_config.get("token", "")
        self.project_id = self.gitlab_config.get("project", "") # Can be "group/project" string or ID
        self.cache_ttl = self.gitlab_config.get("cache_ttl", 3600)
        
        # Determine strict project ID format (URL encoding if it has slashes)
        if "/" in str(self.project_id):
            self.project_id_encoded = requests.utils.quote(str(self.project_id), safe="")
        else:
            self.project_id_encoded = str(self.project_id)

    def _get_cache(self, key: str) -> Dict:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT response_json, fetched_at FROM gitlab_cache WHERE cache_key = ?", (key,))
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
        INSERT OR REPLACE INTO gitlab_cache (cache_key, response_json, fetched_at)
        VALUES (?, ?, ?)
        """, (key, json.dumps(data), datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        
    def _fetch_api(self, endpoint: str) -> Dict:
        if not self.token:
            # GitLab API typically requires token even for public, or limits heavily
            return {}
        
        url = f"{self.base_url}/api/v4/{endpoint}"
        headers = {"PRIVATE-TOKEN": self.token}
        
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"error": "Not Found"}
            else:
                print(f"GitLab API Error {resp.status_code}: {resp.text}")
                return {}
        except Exception as e:
            print(f"GitLab Connection Error: {e}")
            return {}

    def fetch_issue_labels(self, issue_ref: str) -> List[str]:
        # issue_ref could be "#123" or just "123". GitLab IID.
        if not self.project_id:
            return []
        
        try:
            iid = int(str(issue_ref).replace("#", ""))
        except ValueError:
            return []
        
        cache_key = f"gitlab:{self.project_id}:issue:{iid}"
        data = self._get_cache(cache_key)
        
        if not data:
            data = self._fetch_api(f"projects/{self.project_id_encoded}/issues/{iid}")
            if data:
                self._set_cache(cache_key, data)
        
        return data.get("labels", [])

    def fetch_pr_details(self, pr_number: int) -> Dict[str, Any]:
        # GitLab MRs
        if not self.project_id:
            return {}
        
        cache_key = f"gitlab:{self.project_id}:mr:{pr_number}"
        data = self._get_cache(cache_key)
        
        if not data:
            data = self._fetch_api(f"projects/{self.project_id_encoded}/merge_requests/{pr_number}")
            if data:
                self._set_cache(cache_key, data)
        
        return {
            "labels": data.get("labels", []),
            "title": data.get("title", ""),
            "state": data.get("state", "unknown")
        }
