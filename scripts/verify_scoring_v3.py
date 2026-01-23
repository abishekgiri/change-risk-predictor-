from riskbot.scoring.risk_score import RiskScorer
from riskbot.features.types import FeatureVector

# Test Config
config = {
    "critical_paths": {"multiplier": 2.0} # Used for legacy/bonus ref
    # Weights are implicit in code now (Additive)
}
scorer = RiskScorer(config)

print("=== 1. Tiny Churn Test (6 LOC) ===")
# User requirement: 6 LOC should score LOW and never trigger High Size Risk
# New normalized churn_score for 6 LOC should be ~0.02 (minmax(6,0,50)*0.2)
tiny_pr: FeatureVector = {
    "feature_version": "v6",
    "churn_score": 0.02, # Approx for 6 LOC
    "total_churn": 6,
    "files_changed": ["promql/test.go"],
    "is_tier_0": False,
    "critical_subsystems": ["promql/"], # Bonus +15
    "critical_path_score": 0.5, # Crit
    "dependency_risk_score": 0.1,
    "file_historical_risk_score": 0.0
}
# Expect:
# Base = (0.02*40=0.8) + (0.5*30=15) + (0.1*20=2) = 17.8
# Bonus = +15 (Crit Subsystem)
# Total = 32.8 -> WARN (25-50)
# Reason: Touch critical subsystem, but NOT Size Risk
res1 = scorer.calculate_score(tiny_pr)
print(f"Tiny PR: {res1['decision']} (Score: {res1['risk_score']})")
print(f"Reasons: {res1['reasons']}")


print("\n=== 2. Massive Churn Test (>2000 LOC, Safe) ===")
# Should be High Size Risk, maybe FAIL if >50
massive_safe: FeatureVector = {
     "feature_version": "v6",
    "churn_score": 0.9, # Extreme bucket
    "total_churn": 2200,
    "files_changed": ["docs/huge.md", "pkg/legacy.py"],
    "is_tier_0": False,
    "critical_path_score": 0.0,
    "dependency_risk_score": 0.0
}
# Expect:
# Base = (0.9*40=36)
# Bonus = 0
# Total = 36 -> WARN (Medium risk due to size, but not critical)
# Wait, Extreme churn (>1500) might push score higher?
# formula caps at 40 points for churn. 
# So max pure churn score is 40. -> WARN. correct.
res2 = scorer.calculate_score(massive_safe)
print(f"Massive Safe: {res2['decision']} (Score: {res2['risk_score']})")
print(f"Reasons: {res2['reasons']}")


print("\n=== 3. Hard Reject (Big + Critical) ===")
# Etcd case
hard_reject: FeatureVector = {
     "feature_version": "v6",
    "churn_score": 0.8, # High/Extreme
    "total_churn": 1600,
    "files_changed": ["server/etcdserver/api.go"],
    "is_tier_0": False, # Just High
    "critical_subsystems": ["server/"],
    "critical_path_score": 1.0,
    "dependency_risk_score": 0.6, # Broad
    "file_historical_risk_score": 0.0
}
# Expect:
# Base = (0.8*40=32) + (1.0*30=30) + (0.6*20=12) = 74
# Bonus = +15 (Crit) + +10 (Dep > 0.6) = +25
# Total = 99 -> FAIL
res3 = scorer.calculate_score(hard_reject)
print(f"Hard Reject: {res3['decision']} (Score: {res3['risk_score']})")


print("\n=== 4. Tier-0 Gate (Auth) ===")
# Should still be 100
tier0: FeatureVector = {
    "feature_version": "v6",
    "churn_score": 0.05,
    "total_churn": 10,
    "files_changed": ["auth/login.go"],
    "is_tier_0": True,
    "critical_subsystems": ["auth/"],
    "critical_path_score": 1.0
}
res4 = scorer.calculate_score(tier0)
print(f"Tier-0: {res4['decision']} (Score: {res4['risk_score']})")
