from typing import Dict, Any, List, Tuple
from riskbot.config import RISK_DB_PATH
from riskbot.features.types import RawSignals, FeatureVector, FeatureExplanation
from riskbot.features.churn import ChurnEngine
from riskbot.features.criticality import CriticalityEngine
from riskbot.features.history import HistoryEngine
from riskbot.features.dependency import DependencyEngine

class FeatureStore:
    """
    Central contract boundary for feature engineering.
    Converts RawSignals -> FeatureVector.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Initialize Engines
        self.churn_engine = ChurnEngine()
        self.criticality_engine = CriticalityEngine(config)
        self.history_engine = HistoryEngine(config)
        self.dependency_engine = DependencyEngine()
        
        # Load Baselines (Cached)
        # Performance: FeatureStore caches baselines and metadata; 
        # repeated label lookups are served from SQLite cache (sub-ms), keeping CI latency low.
        self.baselines = self._load_repo_baselines()

    def _load_repo_baselines(self) -> Dict[str, float]:
        """
        Load repo stats from DB or return defaults.
        In prod, this queries `repo_baselines` table.
        """
        import sqlite3
        defaults = {
            "log_churn_mean": 4.5,
            "log_churn_std": 1.5,
            "files_changed_p50": 2.0,
            "files_changed_p90": 10.0
        }
        
        try:
            repo = self.config.get("repo_slug") or self.config.get("github", {}).get("repo")
            # If repo not in config, we can't look up specific baselines easily without passing it in build_features
            # But FeatureStore is initialized per repo usually.
            if not repo:
                 return defaults

            conn = sqlite3.connect(RISK_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM repo_baselines WHERE repo = ? ORDER BY updated_at DESC LIMIT 1", (repo,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "log_churn_mean": row["log_churn_mean"],
                    "log_churn_std": row["log_churn_std"],
                    "files_changed_p50": row["files_changed_p50"],
                    "files_changed_p90": row["files_changed_p90"]
                }
        except Exception as e:
            print(f"Error loading baselines: {e}")
            
        return defaults

    def build_features(self, raw: RawSignals) -> Tuple[FeatureVector, FeatureExplanation]:
        """
        Main entry point.
        """
        explanations: FeatureExplanation = []
        
        # 1. Churn
        churn_feats, churn_expl = self.churn_engine.compute_features(raw, self.baselines)
        explanations.extend(churn_expl)
        
        # 2. Criticality
        crit_feats, crit_expl = self.criticality_engine.compute_features(raw)
        explanations.extend(crit_expl)
        
        # 3. Dependency
        dep_feats, dep_expl = self.dependency_engine.compute_features(raw)
        explanations.extend(dep_expl)

        # 4. History (Needs bucket info from others potentially?)
        # For now, HistoryEngine might look up buckets based on raw signals or partial features
        hist_feats, hist_expl = self.history_engine.compute_features(raw, churn_feats, crit_feats, dep_feats)
        explanations.extend(hist_expl)
        
        # Assemble Vector
        # Ensure we have all keys required by FeatureVector type
        vector: FeatureVector = {
            "feature_version": "v6",
            **churn_feats,
            **crit_feats,
            **dep_feats,
            **hist_feats,
            # Metadata pass-through
            "files_changed": raw.get("files_changed"),
            "total_churn": raw.get("total_churn"),
            "commit_count": raw.get("commit_count", 0) # RawSignals might need to be guaranteed to have this
        }
        
        return vector, explanations

    def health_snapshot(self) -> Dict[str, Any]:
        """
        Return diagnostics about current feature store state.
        """
        return {
            "has_baselines": self.baselines["log_churn_mean"] != 4.5, # Assuming 4.5 is default
            "baseline_churn_mean": self.baselines["log_churn_mean"],
            "baseline_files_p90": self.baselines["files_changed_p90"],
            # Check engines
            "criticality_paths_configured": len(self.criticality_engine.critical_paths.get("high", [])) > 0,
            "history_buckets_loaded": len(self.history_engine.bucket_stats) > 0,
            "dependency_graph_loaded": False # Placeholder until graph loaded
        }
