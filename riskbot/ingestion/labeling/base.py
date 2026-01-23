from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class LabelResult:
    """
    Standard output for any labeler strategy.
    """
    value: Optional[int] = None # 1 (Risky), 0 (Safe), None (Unknown)
    source: str = "unknown"
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)
    reason: str = ""
    updated_at: datetime = field(default_factory=datetime.utcnow)

class BaseLabeler(ABC):
    """
    Abstract Base Class for all risk labelers.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    @abstractmethod
    def label(self, entity: Dict[str, Any]) -> LabelResult:
        """
        Analyze an entity (commit/PR wrapper) and return a LabelResult.
        
        Entity schema expected:
        {
            "type": "commit" | "pr",
            "id": "sha" | "pr_number",
            "message": "...",
            "files": [...],
            "linked_issues": [...]
        }
        """
        pass
