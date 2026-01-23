from typing import TypedDict, List, Optional, Dict

class RiskResult(TypedDict):
    """
    Strict contract for Risk Scoring output.
    Used by Server and CI Gates.
    """
    # 1. Scores (0-100 and 0.0-1.0)
    risk_score: int         # 0-100 (Primary for UI)
    risk_prob: float        # 0.0-1.0 (Calibrated Probability)
    
    # 2. Categorical Levels
    risk_level: str         # "LOW", "MEDIUM", "HIGH"
    
    # 3. Decision (CI Gate)
    decision: str           # "PASS", "WARN", "FAIL"
    
    # 4. Explanation
    reasons: List[str]      # Top 3 human-readable reasons
    evidence: List[str]     # Links/Provenance
    
    # 5. Metadata
    model_version: str      # e.g. "baseline-v1" or "logistic-v1"
    feature_version: str    # e.g. "v6"
    components: Dict[str, float] # Detailed component scores (optional)
    data_quality: Optional[str]  # "FULL" or "FALLBACK" - indicates data source quality
