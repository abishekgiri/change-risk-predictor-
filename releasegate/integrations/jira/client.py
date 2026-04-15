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
        self.auth = (self.email, self.token) if self.email and self.token else None
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        self.default_timeout_seconds = float(os.getenv("RELEASEGATE_JIRA_TIMEOUT_SECONDS", "5"))

    @classmethod
    def from_tenant_credentials(cls, tenant_id: str) -> "JiraClient":
        """Create a client using stored OAuth credentials for a tenant."""
        from releasegate.integrations.jira.oauth import get_jira_credentials
        creds = get_jira_credentials(tenant_id)
        if not creds or not creds.get("access_token"):
            raise JiraClientError(f"No Jira credentials found for tenant {tenant_id}")
        client = cls.__new__(cls)
        client.base_url = f"https://api.atlassian.com/ex/jira/{creds['cloud_id']}"
        client.email = ""
        client.token = ""
        client.auth = None
        client.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {creds['access_token']}",
        }
        client.default_timeout_seconds = float(os.getenv("RELEASEGATE_JIRA_TIMEOUT_SECONDS", "5"))
        return client

    @classmethod
    def for_tenant(cls, tenant_id: str) -> "JiraClient":
        """Create a client preferring OAuth credentials, falling back to env vars."""
        try:
            return cls.from_tenant_credentials(tenant_id)
        except JiraClientError:
            return cls()

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

    def list_projects(self) -> List[Dict[str, Any]]:
        resp = self._request(
            "GET",
            "/rest/api/3/project/search",
            params={"maxResults": 200},
            timeout=max(self.default_timeout_seconds, 10),
        )
        if resp.status_code != 200:
            raise JiraDependencyUnavailable(
                f"Jira project lookup failed with status {resp.status_code}"
            )
        payload = resp.json() or {}
        rows = payload.get("values") or payload.get("projects") or []
        projects: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            project_key = str(row.get("key") or "").strip()
            if not project_key:
                continue
            projects.append(
                {
                    "project_key": project_key,
                    "name": str(row.get("name") or project_key),
                    "project_id": str(project_id) if (project_id := row.get("id")) else None,
                }
            )
        projects.sort(key=lambda item: item.get("project_key") or "")
        return projects

    def _list_workflow_transition_rows(self, *, project_key: Optional[str]) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if str(project_key or "").strip():
            params["projectIdOrKey"] = str(project_key).strip()
        resp = self._request(
            "GET",
            "/rest/api/3/workflow/transitions",
            params=params or None,
            timeout=max(self.default_timeout_seconds, 10),
        )
        if resp.status_code != 200:
            raise JiraDependencyUnavailable(
                f"Jira workflow transition lookup failed with status {resp.status_code}"
            )
        payload = resp.json() or {}
        rows = payload.get("values") or []
        return [row for row in rows if isinstance(row, dict)]

    def list_workflows(self, *, project_key: Optional[str] = None) -> List[Dict[str, Any]]:
        rows = self._list_workflow_transition_rows(project_key=project_key)
        workflows: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            workflow_id = str(
                row.get("workflowId")
                or row.get("workflow_id")
                or (row.get("workflow") or {}).get("id")
                or ""
            ).strip()
            workflow_name = str(
                row.get("workflowName")
                or row.get("workflow_name")
                or (row.get("workflow") or {}).get("name")
                or ""
            ).strip()
            if not workflow_id and workflow_name:
                workflow_id = workflow_name.lower().replace(" ", "-")
            if not workflow_id:
                workflow_id = "default"
            if not workflow_name:
                workflow_name = workflow_id

            project_values = row.get("projectKeys") or row.get("projects") or []
            project_keys = [
                str(value).strip()
                for value in project_values
                if str(value).strip()
            ]
            if str(project_key or "").strip():
                project_keys.append(str(project_key).strip())
            normalized_projects = sorted(set(project_keys)) or [str(project_key).strip()] if str(project_key or "").strip() else []
            workflows[workflow_id] = {
                "workflow_id": workflow_id,
                "workflow_name": workflow_name,
                "project_keys": normalized_projects,
            }
        ordered = list(workflows.values())
        ordered.sort(key=lambda item: (str(item.get("workflow_name") or ""), str(item.get("workflow_id") or "")))
        return ordered

    def list_workflow_transitions(
        self,
        *,
        workflow_id: str,
        project_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        rows = self._list_workflow_transition_rows(project_key=project_key)
        normalized_workflow = str(workflow_id or "").strip().lower()
        transitions: List[Dict[str, Any]] = []
        for row in rows:
            row_workflow_id = str(
                row.get("workflowId")
                or row.get("workflow_id")
                or (row.get("workflow") or {}).get("id")
                or ""
            ).strip()
            row_workflow_name = str(
                row.get("workflowName")
                or row.get("workflow_name")
                or (row.get("workflow") or {}).get("name")
                or ""
            ).strip()
            if normalized_workflow:
                workflow_candidates = {
                    row_workflow_id.lower(),
                    row_workflow_name.lower(),
                }
                if normalized_workflow not in workflow_candidates:
                    continue
            transition_id = str(row.get("id") or row.get("transitionId") or "").strip()
            transition_name = str(row.get("name") or row.get("transitionName") or transition_id).strip()
            if not transition_id and not transition_name:
                continue
            if not transition_id:
                transition_id = transition_name.lower().replace(" ", "-")
            transitions.append(
                {
                    "transition_id": transition_id,
                    "transition_name": transition_name,
                    "workflow_id": row_workflow_id or workflow_id,
                    "workflow_name": row_workflow_name or workflow_id,
                }
            )
        deduped: Dict[str, Dict[str, Any]] = {}
        for row in transitions:
            key = f"{row.get('transition_id')}::{row.get('workflow_id')}"
            deduped[key] = row
        ordered = list(deduped.values())
        ordered.sort(key=lambda item: (str(item.get("transition_name") or ""), str(item.get("transition_id") or "")))
        return ordered
