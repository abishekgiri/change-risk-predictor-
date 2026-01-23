from riskbot.scoring.risk_score import RiskScorer
from riskbot.features.types import FeatureVector

scorer = RiskScorer({"critical_paths": {"multiplier": 2.0}}) # Lower multiplier to match script usage

# Case 1: Small but Tier-0 (Auth)
small_tier0: FeatureVector = {
    "feature_version": "v6",
    "churn_score": 0.05, 
    "total_churn": 10,
    "files_changed": ["auth/login.go"],
    "is_tier_0": True,
    "critical_subsystems": ["auth/"],
    "critical_path_score": 1.0
}

# Case 2: Small but Critical (Multiplier test)
small_critical: FeatureVector = {
     "feature_version": "v6",
    "churn_score": 0.05,
    "total_churn": 15,
    "files_changed": ["api/v1/router.go"],
    "is_tier_0": False,
    "critical_path_score": 1.0, 
    "dependency_risk_score": 0.2
}

# Case 3: Large but Safe
large_safe: FeatureVector = {
     "feature_version": "v6",
    "churn_score": 0.4, # Capped
    "total_churn": 800, # Large absolute
    "files_changed": ["docs/README.md"],
    "is_tier_0": False,
    "critical_path_score": 0.0
}

# Case 4: Tiny Critical (Downgrade Rule)
tiny_critical: FeatureVector = {
     "feature_version": "v6",
    "churn_score": 0.4, # High relative
    "total_churn": 35,  # Tiny absolute
    "files_changed": ["tsdb/db.go"],
    "is_tier_0": False,
    "critical_subsystems": ["tsdb/"],
    "critical_path_score": 1.0, 
    "dependency_risk_score": 0.2,
    "file_historical_risk_score": 0.5
}

print("=== Tier-0 Gate Test ===")
res1 = scorer.calculate_score(small_tier0)
print(f"Auth Change: {res1['decision']} (Score: {res1['risk_score']}) - {res1['reasons'][0]}")

print("\n=== Multiplicative Test ===")
res2 = scorer.calculate_score(small_critical)
print(f"API Change: {res2['decision']} (Score: {res2['risk_score']})")

print("\n=== Large Safe Test (Churn Cap) ===")
res3 = scorer.calculate_score(large_safe)
print(f"Docs Change: {res3['decision']} (Score: {res3['risk_score']}) - {res3.get('reasons', [])}")

print("\n=== Tiny Critical Test (Downgrade Verification) ===")
res4 = scorer.calculate_score(tiny_critical)
print(f"Tiny DB Change: {res4['decision']} (Score: {res4['risk_score']}) - {res4.get('reasons', [])}")
