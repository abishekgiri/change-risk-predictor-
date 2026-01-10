from riskbot.config import (
    WEIGHT_CRITICAL_PATH, WEIGHT_HIGH_CHURN, 
    WEIGHT_LARGE_CHANGE, WEIGHT_NO_TESTS
)
from typing import Dict, List, Any

def calculate_score(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate risk score based on features.
    Returns {score: int, reasons: List[str]}
    """
    score = 0
    reasons = []
    
    # Feature extraction
    files_changed = features.get("diff", {}).get("files_changed", 0)
    loc_added = features.get("diff", {}).get("loc_added", 0)
    loc_deleted = features.get("diff", {}).get("loc_deleted", 0)
    critical_paths = features.get("paths", [])
    hotspots = features.get("churn", {}).get("hotspots", [])
    has_tests = features.get("tests", False)
    
    # Rule 1: Critical Path
    if critical_paths:
        score += WEIGHT_CRITICAL_PATH
        reasons.append(f"Touched critical path(s): {', '.join(critical_paths)}")
        
    # Rule 2: High Churn
    if hotspots:
        score += WEIGHT_HIGH_CHURN
        reasons.append(f"High churn in changed files (hotspots: {len(hotspots)})")
        
    # Rule 3: Large Change
    total_loc = loc_added + loc_deleted
    if total_loc > 400:
        score += WEIGHT_LARGE_CHANGE
        reasons.append(f"Large change size (+{loc_added} / -{loc_deleted} LOC)")
        
    # Rule 4: No Tests
    if not has_tests and files_changed > 0:
        # Only penalize if it's code changes without tests. 
        # Ideally check if file extensions are code, but simple for now.
        score += WEIGHT_NO_TESTS
        reasons.append("No tests modified in this PR")
        
    # Clamp 0-100
    score = min(100, max(0, score))
    
    return {
        "score": score,
        "reasons": reasons,
        "risk_level": "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
    }
