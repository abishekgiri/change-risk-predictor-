import unittest
from compliancebot.features import normalize
from compliancebot.features.churn import ChurnEngine
from compliancebot.features.criticality import CriticalityEngine
from compliancebot.features.dependency import DependencyEngine
from compliancebot.features.history import HistoryEngine
from compliancebot.features.types import RawSignals

class TestFeatures(unittest.TestCase):
    
    def test_normalize(self):
        # Edge cases
        self.assertAlmostEqual(normalize.safe_div(10, 0), 0.0)
        self.assertAlmostEqual(normalize.zscore(10, 5, 0), 0.0) # std=0 -> default
        self.assertAlmostEqual(normalize.minmax(5, 10, 10), 0.0) # lo=hi -> 0
        self.assertAlmostEqual(normalize.log1p_int(-5), 0.0)
        self.assertAlmostEqual(normalize.clamp(1.5, 0, 1), 1.0)

    def test_churn_engine(self):
        engine = ChurnEngine()
        baselines = {
            "log_churn_mean": 2.0, 
            "log_churn_std": 1.0,
            "files_changed_p50": 2, 
            "files_changed_p90": 5
        }
        
        # 1. Zero Churn
        raw_zero: RawSignals = {
            "total_churn": 0, "files_changed": [], "per_file_churn": {}
        }
        feats, _ = engine.compute_features(raw_zero, baselines)
        # self.assertAlmostEqual(feats["churn_score"], 0.25) # minmax(zscore(0,2,1)) -> z=-2. map(-1,3)->(0,1). z=-2 clamped 0?
        # log1p(0) = 0. z = (0-2)/1 = -2.
        # minmax(-2, -1, 3) -> (-2 - -1)/4 = -0.25 -> clamped 0.
        self.assertEqual(feats["churn_score"], 0.0)
        
        # 2. High Churn
        # log1p(100) ~ 4.6. z = (4.6-2)/1 = 2.6.
        # map(2.6, -1, 3) -> (2.6+1)/4 = 0.9.
        raw_high: RawSignals = {
            "total_churn": 2000, "files_changed": ["a","b","c","d","e","f"], 
            "per_file_churn": {"a":2000}
        }
        feats, _ = engine.compute_features(raw_high, baselines)
        self.assertGreater(feats["churn_score"], 0.8)
        self.assertEqual(feats["top_file_churn_ratio"], 1.0) # 2000/2000

    def test_criticality_engine(self):
        config = {"critical_paths": {"high": ["auth/"]}}
        engine = CriticalityEngine(config)
        # Mock risk map
        engine.file_risk_map = {"src/old_buggy.py": 0.5}
        
        raw: RawSignals = {"files_changed": ["auth/login.py", "src/old_buggy.py"]}
        feats, _ = engine.compute_features(raw)
        
        self.assertEqual(feats["critical_path_score"], 1.0) # auth matches high
        self.assertEqual(feats["file_historical_risk_score"], 0.5)

    def test_history_engine(self):
        engine = HistoryEngine()
        # Mock buckets
        engine.bucket_stats = {
            "churn_high": {"incidents": 10, "total": 10}, # 100% rate, small sample
            "crit_low": {"incidents": 0, "total": 100} # 0% rate, large sample
        }
        
        # Inputs resulting in churn_high + crit_low
        churn_f = {"churn_score": 0.8}
        crit_f = {"critical_path_score": 0.1}
        dep_f = {"dependency_risk_score": 0.0}
        
        feats, expl = engine.compute_features({}, churn_f, crit_f, dep_f)
        score = feats["historical_risk_score"]
        
        # Should be weighted average. 
        # churn_high: rate ~1.0, weight ~ 0.5 (10/20)
        # crit_low: rate ~0.0, weight ~ 1.0 (100/20 clamped)
        # weighted sum: (1*0.5 + 0*1) / 1.5 = 0.5 / 1.5 = 0.33
        self.assertTrue(0.2 < score < 0.5)

if __name__ == "__main__":
 unittest.main()
