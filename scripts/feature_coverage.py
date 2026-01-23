import sqlite3
import argparse
import sys
import os
import json

sys.path.append(os.getcwd())
from riskbot.config import RISK_DB_PATH
from riskbot.features.feature_store import FeatureStore

def coverage_report(repo: str):
    print(f"=== Feature Coverage Report: {repo} ===")
    
    # 1. FeatureStore Health
    store = FeatureStore({"repo_slug": repo, "critical_paths": {}})
    health = store.health_snapshot()
    
    print("\n[Configuration Health]")
    print(f"Baselines Loaded:     {'✅' if health['has_baselines'] else '❌ (Using defaults)'}")
    print(f"History Buckets:      {'✅' if health['history_buckets_loaded'] else '❌ (Sparse/Missing)'}")
    print(f"Critical Paths:       {'✅' if health['criticality_paths_configured'] else '⚠️ (None configured)'}")
    
    # 2. DB Stats
    conn = sqlite3.connect(RISK_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as c FROM pr_runs WHERE repo = ?", (repo,))
    total = cursor.fetchone()['c']
    
    print(f"\n[Data Stats]")
    print(f"Total PR Runs: {total}")
    
    if total == 0:
        print("No data to analyze.")
        return

    # 3. Feature Population
    # We query pr_runs and check raw columns and features_json if needed
    # Since V6 features might not be in separate columns yet (schema has files_json etc)
    # The 'churn', 'risk_score' are columns.
    # We can check 'features_json' for completeness?
    
    # Let's check bucket stats reliability
    print("\n[History Reliability]")
    cursor.execute("SELECT bucket_id, total_count FROM bucket_stats WHERE repo = ?", (repo,))
    buckets = cursor.fetchall()
    if not buckets:
        print("No bucket stats found (Run backfill!)")
    else:
        min_samples = 20
        warns = 0
        for b in buckets:
            status = "OK"
            if b['total_count'] < min_samples:
                status = "⚠️ Low Sample"
                warns += 1
            print(f"  {b['bucket_id']:<15} : {b['total_count']:<5} {status}")
            
    # 4. Warnings
    print("\n[Action Items]")
    if not health['has_baselines']:
        print("- ⚠️ Run `scripts/backfill_baselines.py` to compute baselines.")
    if not health['history_buckets_loaded']:
        print("- ⚠️ Run `scripts/backfill_baselines.py` to populate history buckets.")
    if health['has_baselines'] and health['history_buckets_loaded']:
        print("- ✅ System appears healthy.")
        
    conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    args = parser.parse_args()
    coverage_report(args.repo)
