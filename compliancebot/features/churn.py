from typing import Dict, Tuple, Any
from compliancebot.features.types import RawSignals, FeatureExplanation
from compliancebot.features import normalize

class ChurnEngine:
    """
    Computes churn-based risk features.
    """
    def compute_features(self, raw: RawSignals, baselines: Dict[str, float]) -> Tuple[Dict[str, float], FeatureExplanation]:
        total_churn = raw["total_churn"]
        files = raw["files_changed"]
        per_file = raw["per_file_churn"]
        
        # 1. Absolute Churn Scoring (Phase 8.5 Fix)
        # User Requirement: 
        # < 50 LOC -> Low
        # 50-300 LOC -> Medium
        # 300-1500 LOC -> High
        # > 1500 LOC -> Extreme
        
        churn_score = 0.0
        if total_churn < 50:
            # Low: 0.0 - 0.20
            # Map 0-50 to 0.0-0.2
            churn_score = normalize.minmax(total_churn, 0, 50) * 0.20
        elif total_churn < 300:
            # Medium: 0.20 - 0.50
            # Map 50-300 to 0.2-0.5
            churn_score = 0.20 + (normalize.minmax(total_churn, 50, 300) * 0.30)
        elif total_churn < 1500:
            # High: 0.50 - 0.80
            # Map 300-1500 to 0.5-0.8
            churn_score = 0.50 + (normalize.minmax(total_churn, 300, 1500) * 0.30)
        else:
            # Extreme: 0.80 - 1.0
            # Map 1500-3000 to 0.8-1.0 (clamped)
            churn_score = 0.80 + (normalize.minmax(total_churn, 1500, 3000) * 0.20)
        
        # Z-score only for legacy stats/logging
        mean = baselines.get("log_churn_mean", 4.5)
        std = baselines.get("log_churn_std", 1.5)
        log_churn = normalize.log1p_int(total_churn)
        z = normalize.zscore(log_churn, mean, std)
        
        # 2. Files Changed Score
        p90 = baselines.get("files_changed_p90", 10.0)
        files_count = len(files)
        files_score = normalize.minmax(files_count, 0, p90 * 1.5)
        
        # 3. Top File Ratio
        max_file_churn = max(per_file.values()) if per_file else 0
        top_ratio = normalize.safe_div(max_file_churn, total_churn)
        
        # Explanations
        expl: FeatureExplanation = []
        if total_churn >= 1500:
            expl.append(f"Extreme Churn: {total_churn} LOC")
        elif total_churn >= 300:
            expl.append(f"High Churn: {total_churn} LOC")
        
        if files_score > 0.8:
            expl.append(f"Broad Impact: {files_count} files changed (>{int(p90)} cutoff)")
        if top_ratio > 0.9 and total_churn > 100:
            expl.append(f"Concentrated Churn: {int(top_ratio*100)}% in single file")
        
        features = {
            "churn_score": churn_score,
            "churn_zscore": z,
            "files_changed_score": files_score,
            "top_file_churn_ratio": top_ratio,
            "total_churn": total_churn
        }
        
        return features, expl

