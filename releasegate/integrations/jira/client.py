import os
import requests
from typing import Dict, Any, List, Optional


class JiraClientError(RuntimeError):
    """Base Jira integration error."""


class JiraDependencyTimeout(JiraClientError):
    """Raised when Jira API calls exceed configured timeout."""


class JiraDependencyUnavailable(JiraClientError):
    """Raised for transport/server errors from Jira dependency."""

class JiraClient:
    def __init__(self):
        self.base_url = os.getenv("JIRA_BASE_URL", "").rstrip("/")
        self.email = os.getenv("JIRA_EMAIL", "")
        self.token = os.getenv("JIRA_API_TOKEN", "")
        self.auth = (self.email, self.token)
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        self.default_timeout_seconds = float(os.getenv("RELEASEGATE_JIRA_TIMEOUT_SECONDS", "5"))

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> requests.Response:
        effective_timeout = timeout if timeout is not None else self.default_timeout_seconds
        try:
            return requests.request(
                method.upper(),
                self._url(path),
                auth=self.auth,
                headers=self.headers,
                timeout=effective_timeout,
                **kwargs,
            )
        except requests.Timeout as exc:
            raise JiraDependencyTimeout(f"Jira {method.upper()} {path} timed out after {effective_timeout}s") from exc
        except requests.RequestException as exc:
            raise JiraDependencyUnavailable(f"Jira {method.upper()} {path} request failed: {exc}") from exc

    def check_permissions(self) -> bool:
        """Health check: verifies credentials and basic read access."""
        if not all([self.base_url, self.email, self.token]):
            return False
        try:
            resp = self._request("GET", "/rest/api/3/myself", timeout=min(self.default_timeout_seconds, 5))
            return resp.status_code == 200
        except JiraClientError:
            return False

    def get_issue_details(self, issue_key: str) -> Dict[str, Any]:
        """Fetch basic issue details (Status, Project, Type)."""
        resp = self._request(
            "GET",
            f"/rest/api/3/issue/{issue_key}",
            params={"fields": "status,project,issuetype"},
            timeout=max(self.default_timeout_seconds, 10),
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
            resp = self._request(
                "GET",
                "/rest/dev-status/1.0/issue/detail",
                params={
                    "issueId": issue_id,
                    "applicationType": "github", # or gitlab, or omit to get all
                    "dataType": "pullrequest"
                },
                timeout=min(self.default_timeout_seconds, 5),
            )
            if resp.status_code == 200:
                return resp.json()
            return {}
        except JiraClientError:
            return {}

    def post_comment_deduped(self, issue_key: str, body: str, dedup_hash: str) -> bool:
        """
        Post a comment only if the last ReleaseGate comment doesn't match the dedup_hash.
        Returns True if posted, False if skipped.
        """
        # 1. Fetch recent comments (limit 5 to save bandwidth)
        try:
            resp = self._request(
                "GET",
                f"/rest/api/3/issue/{issue_key}/comment",
                params={"orderBy": "-created", "maxResults": 5},
                timeout=max(self.default_timeout_seconds, 10),
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
        except JiraClientError:
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
            self._request(
                "POST",
                f"/rest/api/3/issue/{issue_key}/comment",
                json={"body": adf_body},
                timeout=max(self.default_timeout_seconds, 10),
            )
            return True
        except JiraClientError:
            return False

    def set_issue_property(self, issue_key: str, prop_key: str, value: Dict[str, Any]) -> bool:
        """
        Set a Jira issue property (JSON). Returns True on success.
        """
        try:
            resp = self._request(
                "PUT",
                f"/rest/api/3/issue/{issue_key}/properties/{prop_key}",
                json=value,
                timeout=max(self.default_timeout_seconds, 10),
            )
            return resp.status_code in (200, 201, 204)
        except JiraClientError:
            return False

    def get_issue_property(self, issue_key: str, prop_key: str) -> Dict[str, Any]:
        """
        Get a Jira issue property (JSON). Returns {} for missing property.
        Raises JiraDependencyTimeout/JiraDependencyUnavailable on dependency failures.
        """
        resp = self._request(
            "GET",
            f"/rest/api/3/issue/{issue_key}/properties/{prop_key}",
            timeout=max(self.default_timeout_seconds, 10),
        )
        if resp.status_code == 200:
            return resp.json().get("value", {}) or {}
        if resp.status_code == 404:
            return {}
        raise JiraDependencyUnavailable(
            f"Jira issue property fetch failed with status {resp.status_code} for {issue_key}/{prop_key}"
        )

    def list_project_role_names(self, project_key: str) -> List[str]:
        resp = self._request(
            "GET",
            f"/rest/api/3/project/{project_key}/role",
            timeout=max(self.default_timeout_seconds, 10),
        )
        if resp.status_code != 200:
            raise JiraDependencyUnavailable(
                f"Jira project role lookup failed for {project_key} with status {resp.status_code}"
            )
        payload = resp.json() or {}
        return sorted(str(role_name) for role_name in payload.keys())

    def list_group_names(self, max_results: int = 1000) -> List[str]:
        resp = self._request(
            "GET",
            "/rest/api/3/group/bulk",
            params={"maxResults": max_results},
            timeout=max(self.default_timeout_seconds, 10),
        )
        if resp.status_code != 200:
            raise JiraDependencyUnavailable(f"Jira group lookup failed with status {resp.status_code}")
        payload = resp.json() or {}
        values = payload.get("values", [])
        groups = []
        for row in values:
            if isinstance(row, dict):
                name = str(row.get("name") or "").strip()
                if name:
                    groups.append(name)
        return sorted(set(groups))

    def list_transition_ids(self, project_key: str) -> List[str]:
        resp = self._request(
            "GET",
            "/rest/api/3/workflow/transitions",
            params={"projectIdOrKey": project_key},
            timeout=max(self.default_timeout_seconds, 10),
        )
        if resp.status_code != 200:
            raise JiraDependencyUnavailable(
                f"Jira transition lookup failed for {project_key} with status {resp.status_code}"
            )
        payload = resp.json() or {}
        transitions = payload.get("values", [])
        ids = []
        for row in transitions:
            if isinstance(row, dict):
                value = str(row.get("id") or "").strip()
                if value:
                    ids.append(value)
        return sorted(set(ids))
