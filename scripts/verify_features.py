import os
import sys
import json
# Add root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from riskbot.features.feature_store import FeatureStore
from riskbot.scoring.risk_score import RiskScorer

def verify_feature_flow():
    print("--- Verifying Core Intelligence Layer (Phase 6/8) ---")

    # Mock Config
    config = {
        "critical_paths": {
            "high": ["config/", "auth/", "db/"],
            "medium": ["util"]
        },
        "weights": {"history": 0.4} # Custom weight test
    }
    
    # Instantiate Store & Scorer
    store = FeatureStore(config)
    scorer = RiskScorer(config) 
    
    # 1. Simulate RISKY PR
    # - High churn (assume repo mean is small)
    # - Critical files touched
    # - Scattered (many files)
    print("\n[Simulating RISKY PR]")
    raw_risky = {
        "repo_slug": "test/repo",
        "entity_type": "pr",
        "entity_id": "100",
        "timestamp": "2023-01-01",
        "files_changed": ["config/database.yaml", "auth/login.py"] + [f"src/util_{i}.py" for i in range(48)],
        "lines_added": 1500,
        "lines_deleted": 200,
        "total_churn": 1700,
        "per_file_churn": {"config/database.yaml": 50, "auth/login.py": 50}, # Partial map ok for sim
        "touched_services": ["auth", "db", "frontend"], # Explicit blast radius
        "linked_issue_ids": [],
        "author": "dev",
        "branch": "feat/risky"
    }
    
    # feature store
    feats_risky, expl_risky = store.build_features(raw_risky)
    print("Feature Vector (Risky):")
    print(json.dumps(feats_risky, indent=2))
    
    # score
    result_risky = scorer.calculate_score(feats_risky, evidence=expl_risky)
    print("Score Result (Risky):")
    print(json.dumps(result_risky, indent=2))
    
    # Check
    score = result_risky["risk_score"]
    decision = result_risky["decision"]
    
    if score < 50:
         print(f"❌ FAIL: Risky PR score too low! ({score})")
    elif decision == "PASS":
         print(f"❌ FAIL: Decision is PASS but should warn/fail! ({decision})")
    else:
         print(f"✅ PASS: Risky PR detected (Score {score}, Decision {decision}).")

    # 2. Simulate SAFE PR
    # - Low churn
    # - No critical files
    # - Focused
    print("\n[Simulating SAFE PR]")
    raw_safe = {
        "repo_slug": "test/repo",
        "entity_type": "pr",
        "entity_id": "101",
        "timestamp": "2023-01-01",
        "files_changed": ["docs/readme.md"],
        "lines_added": 10,
        "lines_deleted": 5,
        "total_churn": 15,
        "per_file_churn": {"docs/readme.md": 15},
        "touched_services": [],
        "linked_issue_ids": [],
        "author": "writer",
        "branch": "docs/fix"
    }
    
    feats_safe, expl_safe = store.build_features(raw_safe)
    print("Feature Vector (Safe):")
    print(json.dumps(feats_safe, indent=2))
    
    result_safe = scorer.calculate_score(feats_safe, evidence=expl_safe)
    print("Score Result (Safe):")
    print(json.dumps(result_safe, indent=2))
    
    score_safe = result_safe["risk_score"]
    if score_safe > 30:
         print(f"❌ FAIL: Safe PR score too high! ({score_safe})")
    else:
         print(f"✅ PASS: Safe PR validated (Score {score_safe}).")

if __name__ == "__main__":
    verify_feature_flow()
