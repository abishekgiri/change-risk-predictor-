import sqlite3
import json
from typing import Dict, Tuple, Any, List
from compliancebot.config import DB_PATH
from compliancebot.features.types import RawSignals, FeatureExplanation
from compliancebot.features import normalize

class CriticalityEngine:
    """
    Computes Structural (Config) and Empirical (History) criticality.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.critical_paths = config.get("critical_paths", {})
        self.file_risk_map = self._build_historical_risk_map()

    def _build_historical_risk_map(self) -> Dict[str, float]:
        """
        Scan DB to build {filename: incident_rate} map.
        Gracefully handles missing DB (e.g. in CI or fresh install).
        """
        import os
        if not os.path.exists(DB_PATH):
            return {}

        conn = sqlite3.connect(DB_PATH)
        try:
            query = """
            SELECT files_json, label_value 
            FROM pr_runs 
            WHERE label_value IS NOT NULL AND files_json IS NOT NULL
            """
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            
            file_counts = {} # file -> {"changes": 0, "incidents": 0}
            
            for files_str, label_val in rows:
                try:
                    files = json.loads(files_str)
                    is_incident = 1 if label_val == 1 else 0
                    
                    for f in files:
                        if f not in file_counts:
                            file_counts[f] = {"changes": 0, "incidents": 0}
                        file_counts[f]["changes"] += 1
                        file_counts[f]["incidents"] += is_incident
                except Exception:
                    continue
            
            risk_map = {}
            for f, stats in file_counts.items():
                if stats["changes"] > 0:
                    risk_map[f] = stats["incidents"] / stats["changes"]
            
            return risk_map
        except Exception as e:
            print(f"Warning: Error building historical risk map: {e}")
            return {}
        finally:
            conn.close()

    def compute_features(self, raw: RawSignals) -> Tuple[Dict[str, float], FeatureExplanation]:
        files = raw["files_changed"]
        
        # 1. Structural (Config) Risk
        max_config_score = 0.0
        matched_path = ""
        
        high_paths = []
        med_paths = []
        low_paths = []
        cp = self.critical_paths
        
        if not cp:
            high_paths = ["api/", "auth/", "security/", "staging/src/k8s.io/client-go/", "staging/src/k8s.io/cli-runtime/"]
            med_paths = ["charts/", "templates/", "third_party/", "core/", "infra/"]
        
        if isinstance(cp, dict):
            high_paths = cp.get("high", [])
            med_paths = cp.get("medium", [])
            low_paths = cp.get("low", [])
        elif isinstance(cp, list):
            high_paths = cp
        
        test_files_count = 0 
        
        for f in files:
            is_test = False
            for p in low_paths:
                if p in f:
                    test_files_count += 1
                    is_test = True
                    break
            
            if is_test: continue 
            
            for p in high_paths:
                if p in f: 
                    max_config_score = max(max_config_score, 1.0)
                    matched_path = p
            for p in med_paths:
                if p in f: 
                    max_config_score = max(max_config_score, 0.5)
                    if not matched_path: matched_path = p
        
        # 2. Historical (Empirical) Risk
        max_history_score = 0.0
        risky_file = ""
        history_source = ""
        risky_recent_count = 0 
        
        for f in files:
            score = self.file_risk_map.get(f, 0.0)
            if score > max_history_score:
                max_history_score = score
                risky_file = f
                history_source = "incident_history"

        file_history = raw.get("file_history", {})
        from datetime import datetime, timedelta, timezone
        import dateutil.parser
        now = datetime.now(timezone.utc)
        
        for f, details in file_history.items():
            if not details: continue
            
            recent_count = 0
            for d_str in details:
                try:
                    dt = dateutil.parser.isoparse(d_str)
                    if (now - dt).days <= 30:
                        recent_count += 1
                except:
                    continue
            
            hotspot_score = 0.0
            if recent_count >= 10: hotspot_score = 0.9
            elif recent_count >= 5: hotspot_score = 0.5
            elif recent_count >= 3: hotspot_score = 0.3
            
            if hotspot_score > max_history_score:
                max_history_score = hotspot_score
                risky_file = f
                history_source = "hotspot"
                risky_recent_count = recent_count 
        
        expl: FeatureExplanation = []
        if max_config_score >= 0.9:
            expl.append(f"Critical Path: Touched '{matched_path}'")
        
        if max_history_score > 0.2:
            if history_source == "incident_history":
                expl.append(f"Risky File: '{risky_file}' has {int(max_history_score*100)}% incident rate")
            else:
                expl.append(f"Hotspot: '{risky_file}' modified frequently ({risky_recent_count} times in 30d)")

        # 0. Check Tier-0 (Hard Gate)
        tier0_paths = []
        if isinstance(cp, dict):
            tier0_paths = cp.get("tier_0", [])
        
        matched_tier0 = False
        for f in files:
            for p in tier0_paths:
                if p in f:
                    matched_tier0 = True
                    matched_path = p 
                    break
            if matched_tier0: break
        
        return {
            "critical_path_score": max_config_score,
            "file_historical_risk_score": max_history_score,
            "critical_subsystems": [matched_path] if matched_path else [],
            "is_tier_0": matched_tier0,
            "test_files_count": test_files_count
        }, expl

