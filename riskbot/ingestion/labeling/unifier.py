from typing import List, Dict, Any, Optional
from riskbot.ingestion.labeling.base import LabelResult

class LabelUnifier:
    """
    Unifies multiple label signals into a single ground truth.
    Policy: Risky (1) > Safe (0) > Unknown (None)
    Constraint: Only trust labels with confidence >= min_high_confidence.
    """
    def __init__(self, min_high_confidence: float = 0.85):
        self.min_confidence = min_high_confidence

    def unify(self, results: List[LabelResult]) -> LabelResult:
        if not results:
            return LabelResult(value=None, source="none", confidence=0.0)

        # 1. Filter for High Confidence
        high_conf_results = [r for r in results if r.confidence >= self.min_confidence]
        
        # 2. Check for RISKY (1)
        risky = [r for r in high_conf_results if r.value == 1]
        if risky:
            # Pick highest confidence risky label
            winner = max(risky, key=lambda x: x.confidence)
            winner.source = f"{winner.source} (unified)"
            return winner
            
        # 3. Check for SAFE (0)
        safe = [r for r in high_conf_results if r.value == 0]
        if safe:
            winner = max(safe, key=lambda x: x.confidence)
            winner.source = f"{winner.source} (unified)"
            return winner
            
        # 4. Fallback to Unknown (NULL)
        # Even if we have low-conf keywords, we return Unknown to protect calibration.
        return LabelResult(
            value=None, 
            source="unknown", 
            confidence=0.0, 
            reason="No high-confidence labels found"
        )
