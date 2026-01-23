import unittest
import json
import glob
import os
from typing import Dict, Any
from riskbot.features.feature_store import FeatureStore
from riskbot.scoring.risk_score import RiskScorer
from riskbot.features.types import RawSignals

class TestGoldenFixtures(unittest.TestCase):
    def setUp(self):
        # Setup config with known critical paths for determinism
        self.config = {
            "critical_paths": {
                "high": ["auth/", "config/", "infra/"],
                "medium": ["api/"]
            },
            "weights": {
                "history": 0.35,
                "dependency": 0.20,
                "churn": 0.20,
                "criticality": 0.15,
                "complexity": 0.10
            }
        }
        self.store = FeatureStore(self.config)
        self.scorer = RiskScorer(self.config)
        
        # Mock baselines to ensure tests don't depend on DB state
        # These are "average" repo stats
        # log(50) ~ 3.9, log(1000) ~ 6.9
        self.store.baselines = {
            "log_churn_mean": 4.0,  # ~55 lines
            "log_churn_std": 1.5,   # decent spread
            "files_changed_p50": 3,
            "files_changed_p90": 15
        }
        # Mock bucket stats for history engine -> Assume sparse history for these tests 
        # unless we explicitly mock HistoryEngine.bucket_stats? 
        # FeatureStore.history_engine initialized in __init__.
        # Let's mock it directly.
        self.store.history_engine.bucket_stats = {
            "churn_high": {"incidents": 5, "total": 10}, # 50% risk
            "churn_med": {"incidents": 1, "total": 20},  # 5% risk
            "churn_low": {"incidents": 0, "total": 50}   # 0% risk
        }
        # Mock file risk map for CriticalityEngine
        self.store.criticality_engine.file_risk_map = {} 

    def test_fixtures(self):
        fixture_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        fixture_files = glob.glob(os.path.join(fixture_dir, "*.json"))
        
        if not fixture_files:
            self.fail("No golden fixtures found in tests/fixtures/")
            
        for fpath in fixture_files:
            with self.subTest(fixture=os.path.basename(fpath)):
                print(f"Running fixture: {os.path.basename(fpath)}")
                with open(fpath, "r") as f:
                    data = json.load(f)
                
                raw = data["raw_signals"]
                expect = data["expectations"]
                
                # 1. Build Features
                features, explanations = self.store.build_features(raw)
                
                # 2. Score
                score_data = self.scorer.calculate_score(features, evidence=explanations)
                
                # 3. Assertions
                # Risk Score
                score = score_data["score"]
                if "risk_score_min" in expect:
                    self.assertGreaterEqual(score, expect["risk_score_min"], 
                        f"Score {score} < min {expect['risk_score_min']}")
                if "risk_score_max" in expect:
                    self.assertLessEqual(score, expect["risk_score_max"], 
                        f"Score {score} > max {expect['risk_score_max']}")
                        
                # Feature Value Checks
                for feat, checks in expect.get("feature_checks", {}).items():
                    val = features.get(feat, 0.0)
                    if "min" in checks:
                        self.assertGreaterEqual(val, checks["min"], f"{feat}={val} < min {checks['min']}")
                    if "max" in checks:
                        self.assertLessEqual(val, checks["max"], f"{feat}={val} > max {checks['max']}")
                    if "eq" in checks:
                        self.assertAlmostEqual(val, checks["eq"], delta=0.01, msg=f"{feat}={val} != {checks['eq']}")
                        
                # Explanation Checks
                reasons = " ".join(score_data["reasons"])
                for phrase in expect.get("explanations_contain", []):
                    self.assertIn(phrase, reasons, f"Missing reason: '{phrase}' in '{reasons}'")
                
                for phrase in expect.get("explanations_must_not_contain", []):
                    self.assertNotIn(phrase, reasons, f"Unexpected reason: '{phrase}' in '{reasons}'")

if __name__ == "__main__":
    unittest.main()
