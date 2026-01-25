from typing import Dict, Tuple, Any
from compliancebot.features.types import RawSignals, FeatureExplanation
from compliancebot.features import normalize

class HistoryEngine:
    """
    Computes Empirical Failure Correlation using Buckets.
    No ML. Uses Laplace smoothing on historical stats.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        # In prod: Load bucket stats from DB
        # {bucket_id: {incidents: 5, total: 100}}
        self.bucket_stats = self._load_bucket_stats()
        self.repo_base_rate = 0.05 # Default if unknown

    def _load_bucket_stats(self) -> Dict[str, Dict[str, int]]:
        import sqlite3
        from compliancebot.config import DB_PATH
        stats = {}
        
        try:
            repo = self.config.get("repo_slug") or self.config.get("github", {}).get("repo")
            if not repo: return {}
            
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT bucket_id, incident_count, total_count FROM bucket_stats WHERE repo = ?", (repo,))
            rows = cursor.fetchall()
            conn.close()
            
            for r in rows:
                stats[r["bucket_id"]] = {
                    "incidents": r["incident_count"], 
                    "total": r["total_count"]
                }
        except Exception as e:
            print(f"Error loading bucket stats: {e}")
        
        return stats

    def compute_features(self, 
        raw: RawSignals, 
        churn_feats: Dict[str, float], 
        crit_feats: Dict[str, float], 
        dep_feats: Dict[str, float]) -> Tuple[Dict[str, float], FeatureExplanation]:
        
        # 1. Determine Buckets for this PR
        buckets = []
        
        # Churn Bucket
        c_score = churn_feats.get("churn_score", 0)
        if c_score > 0.7: buckets.append("churn_high")
        elif c_score < 0.2: buckets.append("churn_low")
        else: buckets.append("churn_med")
        
        # Criticality Bucket
        crit_score = crit_feats.get("critical_path_score", 0)
        if crit_score > 0.5: buckets.append("crit_high")
        else: buckets.append("crit_low")
        
        # Dependency Bucket
        dep_score = dep_feats.get("dependency_risk_score", 0)
        if dep_score > 0.5: buckets.append("dep_high")
        else: buckets.append("dep_low")
        
        # 2. Lookup Stats & Compute Weighted Rate
        weighted_sum = 0.0
        total_weight = 0.0
        
        min_samples = 20.0
        
        relevant_stats = []
        
        for b_id in buckets:
            stats = self.bucket_stats.get(b_id, {"incidents": 0, "total": 0})
            incidents = stats["incidents"]
            total = stats["total"]
            
            # Laplace Rate
            rate = normalize.laplace_rate(incidents, total)
            
            # Weight by sample size confidence (cap at 1.0)
            weight = normalize.clamp(total / min_samples, 0.0, 1.0)
            
            if total > 0:
                weighted_sum += rate * weight
                total_weight += weight
                relevant_stats.append((b_id, rate, total))
        
        # 3. Aggregate
        if total_weight > 0.1:
            hist_score = weighted_sum / total_weight
        else:
            # Fallback to repo base rate (or low default)
            hist_score = self.repo_base_rate
        
        # Normalize?
        hist_score = normalize.clamp(hist_score, 0.0, 1.0)
        
        expl: FeatureExplanation = []
        if hist_score > 0.2:
            expl.append(f"Historical Risk: Similar changes fail ~{int(hist_score*100)}% of time")
            # Details
            for b_id, rate, n in relevant_stats:
                if rate > 0.2 and n > 5:
                    expl.append(f" - Bucket '{b_id}': rate={rate:.2f} (n={n})")
        
        features = {
            "historical_risk_score": hist_score
        }
        return features, expl

