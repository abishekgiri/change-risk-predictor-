from compliancebot.config import (
    WEIGHT_CRITICAL_PATH, WEIGHT_HIGH_CHURN, 
    WEIGHT_LARGE_CHANGE, WEIGHT_NO_TESTS,
    SEVERITY_THRESHOLD_HIGH, SEVERITY_THRESHOLD_MEDIUM
)
from typing import Dict, List, Any
import pickle
import os
import pandas as pd
import json

def load_model():
    """Load model if exists, otherwise return None."""
    try:
        model_path = "data/model.pkl"
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                return pickle.load(f)
    except Exception as e:
        print(f"Warning: Could not load ML model: {e}")
    return None

def calculate_score(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate risk score based on hybrid approach: max(heuristic, ml_model).
    Returns {score: int, reasons: List[str]}
    """
    heuristic_score = 0
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
        heuristic_score += WEIGHT_CRITICAL_PATH
        reasons.append(f"Touched critical path(s): {', '.join(critical_paths)}")
    
    # Rule 2: High Churn
    if hotspots:
        heuristic_score += WEIGHT_HIGH_CHURN
        reasons.append(f"High churn in changed files (hotspots: {len(hotspots)})")
    
    # Rule 3: Large Change
    total_loc = loc_added + loc_deleted
    if total_loc > 400:
        heuristic_score += WEIGHT_LARGE_CHANGE
        reasons.append(f"Large change size (+{loc_added} / -{loc_deleted} LOC)")
    
    # Rule 4: No Tests
    if not has_tests and files_changed > 0:
        heuristic_score += WEIGHT_NO_TESTS
        reasons.append("No tests modified in this PR")
    
    # --- 2. ML Scoring (Inference) ---
    model_score = 0
    model = load_model()
    
    if model:
        try:
            # Prepare single-row DataFrame for prediction
            flat_features = pd.json_normalize([features])
            flat_features = flat_features.fillna(0)
            
            if hasattr(model, "feature_names_in_"):
                # Align columns, adding missing as 0
                missing_cols = set(model.feature_names_in_) - set(flat_features.columns)
                for c in missing_cols:
                    flat_features[c] = 0
                flat_features = flat_features[model.feature_names_in_]
            
            # Predict probability of Class 1 (Risky)
            prob_risky = model.predict_proba(flat_features)[0][1]
            model_score = int(prob_risky * 100)
            
            if model_score > 0:
                reasons.append(f"ML Model Risk Prediction: {model_score}%")
            else:
                reasons.append(f"ML Model Risk Prediction: {model_score}% (Hybrid scoring ready; ML activates once enough labeled data exists)")
        except Exception as e:
            print(f"ML Inference Error: {e}")
    
    # --- 3. Hybrid Enforcement ---
    final_score = max(heuristic_score, model_score)
    
    if model_score > heuristic_score:
        reasons.append("(ML Model overrode heuristic score)")

    # Clamp 0-100
    final_score = min(100, max(0, final_score))
    
    return {
        "score": final_score,
        "reasons": reasons,
        "risk_level": "HIGH" if final_score >= SEVERITY_THRESHOLD_HIGH else "MEDIUM" if final_score >= SEVERITY_THRESHOLD_MEDIUM else "LOW"
    }
