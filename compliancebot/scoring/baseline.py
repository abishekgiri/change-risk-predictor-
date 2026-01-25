from typing import Dict, List, Tuple
from compliancebot.features.types import FeatureVector
from compliancebot.features import normalize

DEFAULT_WEIGHTS = {
 "churn": 0.25,
 "criticality": 0.25,
 "file_history": 0.20,
 "dependency": 0.20, # Blast radius
 "history": 0.10 # Global repo history
}

def compute_baseline_score(features: FeatureVector, 
    weights: Dict[str, float] = None) -> Tuple[int, List[str], Dict[str, float]]:
    """
    Compute heuristic risk score (0-100) from features.
    Returns: (score, reasons, component_scores)
    """
    w = weights or DEFAULT_WEIGHTS
    
    # 1. Normalize Inputs (Features are already 0-1)
    # Extract
    churn_score = features.get("churn_score", 0.0)
    
    # Criticality: Max of structural config or historical file risk
    crit_struct = features.get("critical_path_score", 0.0)
    file_hist = features.get("file_historical_risk_score", 0.0)
    
    dep_score = features.get("dependency_risk_score", 0.0)
    hist_score = features.get("historical_risk_score", 0.0) # Global/Bucket
    
    # 2. Weighted Sum
    raw_score = (
        churn_score * w.get("churn", 0.25) +
        crit_struct * w.get("criticality", 0.25) +
        file_hist * w.get("file_history", 0.20) +
        dep_score * w.get("dependency", 0.20) +
        hist_score * w.get("history", 0.10)
    )
    
    # Clamp and Scale
    final_score = int(min(100, max(0, raw_score * 100)))
    
    # 3. Explainability
    # Generate reasons based on contributions
    reasons = []
    
    if churn_score > 0.5:
        reasons.append(f"High Churn Risk ({int(churn_score*100)}%)")
    elif churn_score > 0.3:
        reasons.append(f"Moderate Churn ({int(churn_score*100)}%)")
    
    if crit_struct > 0.1:
        reasons.append(f"Touches Critical Paths ({int(crit_struct*100)}%)")
    
    if file_hist > 0.2:
        reasons.append(f"Files have incident history ({int(file_hist*100)}% reliability)")
    
    if dep_score > 0.3:
        reasons.append(f"High Blast Radius ({int(dep_score*100)}%)")
    
    if hist_score > 0.3:
        reasons.append(f"Pattern looks risky historicaly ({int(hist_score*100)}% fail rate)")

    components = {
        "churn": churn_score,
        "criticality": crit_struct,
        "file_history": file_hist,
        "dependency": dep_score,
        "history": hist_score
    }
    
    return final_score, reasons, components

