from dataclasses import dataclass
from typing import List

@dataclass
class ReviewPriorityResult:
    """
    Review priority assessment for a PR.
    Deterministic: same inputs → same priority.
    """
    # Identity
    pr_id: str
    
    # Priority
    priority: str  # P0 | P1 | P2
    label: str  # "Immediate" | "Normal" | "Low"
    
    # Explainability
    rationale: List[str]  # Short bullet reasons (max 3)
    recommendation: str  # Fixed action text
    
    # Metadata (Enterprise Polish)
    repo: str = ""
    risk_score: int = 0
    decision: str = ""
    data_quality: str = "FULL"
