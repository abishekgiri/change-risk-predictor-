from typing import TypedDict, List, Dict, Any, Optional

class Contributor(TypedDict):
    """
    A single risk contributor with deterministic explanation.
    """
    # Stable identifier
    id: str  # "churn" | "critical_path" | "file_history" | "dependency" | "history_bucket" | "routine_change"
    
    # Display
    title: str  # Short label: "High churn", "Critical paths touched"
    
    # Quantitative
    impact: float  # 0-1 normalized contribution (sum to 1 across all)
    severity: str  # "LOW" | "MEDIUM" | "HIGH"
    
    # Explanation
    summary: str  # One-line suitable for Check title bullet
    details: List[str]  # 2-5 deterministic bullets
    
    # Auditability
    evidence: List[str]  # Issue links, revert SHAs, downstream services
    metrics: Dict[str, Any]  # Raw numbers used in text (z-score, rates, counts)

class ExplanationReport(TypedDict):
    """
    Complete explanation for a risk assessment.
    Deterministic: same inputs → same output.
    """
    # Risk Assessment (from RiskResult)
    risk_score: int  # 0-100
    risk_prob: float  # 0.0-1.0
    decision: str  # PASS | WARN | FAIL
    risk_level: str  # LOW | MEDIUM | HIGH
    
    # Contributors (ranked)
    top_contributors: List[Contributor]  # Top 3-5 for display
    all_contributors: Optional[List[Contributor]]  # All computed (debugging)
    
    # Metadata
    explain_version: str  # "v1"
    feature_version: str  # "v6"
    model_version: Optional[str]  # "baseline-v1" or "logistic-v1"
