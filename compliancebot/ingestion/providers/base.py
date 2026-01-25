from typing import List, Dict, Any

class GitProvider:
    """
    Abstract Dynamic Provider for fetching PR/Issue metadata.
    Enables Phase 6: Enterprise Context (Labels & Metadata).
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def fetch_issue_labels(self, issue_ref: str) -> List[str]:
        """Fetch labels for a given issue reference."""
        raise NotImplementedError

    def fetch_pr_details(self, pr_number: int) -> Dict[str, Any]:
        """Fetch details for a given Pull Request."""
        raise NotImplementedError
