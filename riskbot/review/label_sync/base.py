from typing import Protocol, List

class LabelSyncProvider(Protocol):
    """
    Interface for label sync providers (GitHub, GitLab).
    """
    def ensure_label_exists(self, name: str, color: str, description: str) -> None:
        """Create label if it doesn't exist."""
        ...
    
    def get_labels(self, pr_number: int) -> List[str]:
        """Get current labels on PR/MR."""
        ...
    
    def add_labels(self, pr_number: int, labels: List[str]) -> None:
        """Add labels to PR/MR."""
        ...
    
    def remove_labels(self, pr_number: int, labels: List[str]) -> None:
        """Remove labels from PR/MR."""
        ...
