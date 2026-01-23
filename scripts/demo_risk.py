import sys
import os
import json
from pprint import pprint

# Add project root to python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riskbot.scoring.risk_score import RiskScorer
from riskbot.scoring.calibration import RiskCalibrator

def demo_risk_scoring():
    print("🚀 RiskBot V2: Scoring & Calibration Demo")
    print("=========================================")
    
    scorer = RiskScorer()
    calibrator = RiskCalibrator()
    calibrator.fit() # Load curve
    
    # CASE 1: The "Safe" Docs Change
    # ------------------------------------------------
    print("\n[Case 1] Safe Docs Change")
    feat_safe = {
        "churn": 45,
        "files_count": 2,
        "files_list": ["docs/index.md", "README.md"],
        "entropy": 0.2, # Low complexity
        "critical_files_count": 0,
        "blast_radius": 0,
        "hotspot_score": 0.05
    }
    
    res_safe = scorer.calculate_score(feat_safe)
    prob_safe = calibrator.predict_proba(res_safe['score'])
    
    print(f"Risk Score: {res_safe['score']} / 100")
    print(f"Probability: {prob_safe:.2%}")
    print("Reasons:")
    for r in res_safe['reasons']:
        print(f" - {r}")
    if not res_safe['reasons']:
        print(" - (None, routine change)")

    if res_safe['score'] > 80: print("❌ BLOCKED")
    else: print("✅ PASSED")


    # CASE 2: The "Risky" Auth Refactor
    # ------------------------------------------------
    print("\n[Case 2] Critical Auth Refactor")
    feat_risky = {
        "churn": 1240, # High churn
        "files_count": 15,
        "files_list": ["auth/login.py", "auth/user.py", "config/settings.py"],
        "entropy": 0.85, # Scattered changes
        "critical_files_count": 3,
        "blast_radius": 4, # Impacts 4 downstream services
        "hotspot_score": 0.98 # Top 2% hotspot (config.py)
    }
    
    res_risky = scorer.calculate_score(feat_risky)
    prob_risky = calibrator.predict_proba(res_risky['score'])
    
    print(f"Risk Score: {res_risky['score']} / 100")
    print(f"Probability: {prob_risky:.2%}")
    print("Reasons:")
    for r in res_risky['reasons']:
        print(f" - {r}")
        
    if res_risky['score'] >= 80: print("❌ BLOCKED")
    else: print("✅ PASSED")
    
if __name__ == "__main__":
    demo_risk_scoring()
