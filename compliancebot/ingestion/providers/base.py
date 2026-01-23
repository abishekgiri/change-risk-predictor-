from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class GitProvider(ABC):
    """
    Abstract interface for fetching metadata from a Git host (GitHub, GitLab, etc).
    Decouples ingestion logic from the specific API implementation.
    """
    
    @abstractmethod
    def fetch_issue_labels(self, issue_ref: str) -> List[str]:
        """
        Fetch labels for a given issue/PR reference.
        ref format depends on provider, but typically "#123" or "123".
        Returns list of label names e.g. ["bug", "sev1"].
        """
        pass
        
    @abstractmethod
    def fetch_pr_details(self, pr_number: int) -> Dict[str, Any]:
        """
        Fetch details for a PR (title, body, state, labels).
        """
        pass
