from riskbot.scoring.risk_score import RiskScorer
from riskbot.features.types import FeatureVector

# Test Config with new path structure
config = {
    "critical_paths": {
        "bonuses": {"core": 25, "high": 15, "medium": 10, "low": 5},
        "core": ["auth/", "consensus/"],
        "high": ["api/", "tsdb/", "promql/"], # promql is high
        "low": ["test/", "testdata/"] # Added testdata
    }
}
scorer = RiskScorer(config)

print("=== 1. Test Data vs Core Engine ===")
# Case A: Change to Core Engine
core_change: FeatureVector = {
    "feature_version": "v6",
    "churn_score": 0.1, 
    "total_churn": 20,
    "files_changed": ["promql/engine.go"],
    "critical_path_score": 0.8 # High
}
# Expect: Base ~25 + Bonus 15 (High) = 40 (WARN)
res_core = scorer.calculate_score(core_change)
print(f"Core Engine: {res_core['decision']} (Score: {res_core['risk_score']}) - {res_core['reasons']}")

# Case B: Change to Test Data
test_change: FeatureVector = {
     "feature_version": "v6",
    "churn_score": 0.1, 
    "total_churn": 20,
    "files_changed": ["promql/testdata/query.test"],
    "critical_path_score": 0.0 # Not critical per feature engine yet, but let's see bonus
}
# Note: In real app, `CriticalityEngine` sets the score. 
# Here we test if RiskScorer bonus logic picks up the path even if score is low
# Actually, RiskScorer iterates files_changed to find bonus.
res_test = scorer.calculate_score(test_change)
# Expect: Hit "promql/" (High) ? 
# Wait, "promql/testdata" matches "promql/" pattern. 
# We need to ensure we don't over-match.
# Current logic: "promql/" is High. So "promql/testdata" will match High.
# UNLESS we put "testdata" in exclusion or ensure Low is checked?
# Our logic checks Core -> High -> Medium. "promql/" is in High.
# So "promql/testdata" will match High.
# This reveals we need an EXCLUSION or ORDERING fix in config if we want testdata to be Low.
print(f"Test Data: {res_test['decision']} (Score: {res_test['risk_score']}) - {res_test['reasons']}")


print("\n=== 2. UX Message Check ===")
extreme_churn: FeatureVector = {
     "feature_version": "v6",
    "churn_score": 0.9,
    "total_churn": 25000,
    "files_changed": ["vendor/big.go"]
}
res_ux = scorer.calculate_score(extreme_churn)
print(f"Extreme: {res_ux['decision']} - {res_ux['reasons'][0]}")
