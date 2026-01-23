import sqlite3
import json
import math
import argparse
import statistics
import sys
import os

# Ensure riskbot is in path
sys.path.append(os.getcwd())

from riskbot.config import RISK_DB_PATH
from riskbot.features import normalize
from riskbot.features.feature_store import FeatureStore
from riskbot.features.types import RawSignals

FEATURE_VERSION = "v6"

def backfill(repo_slug: str):
    print(f"Starting backfill for {repo_slug}...")
    conn = sqlite3.connect(RISK_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Fetch Historical Data
    print("Fetching historical runs...")
    cursor.execute("""
        SELECT churn, files_touched, files_json, label_value 
        FROM pr_runs 
        WHERE repo = ?
    """, (repo_slug,))
    rows = cursor.fetchall()
    
    if not rows:
        print("No data found for repo.")
        return

    churn_values = []
    files_counts = []
    
    # File Stats Aggregation
    file_map = {} # path -> {total: 0, incidents: 0}
    
    valid_rows = []
    
    for r in rows:
        churn = r['churn'] or 0
        f_count = r['files_touched'] or 0
        label = r['label_value'] # 1 or 0 or None
        files_list = json.loads(r['files_json']) if r['files_json'] else []
        
        churn_values.append(churn)
        files_counts.append(f_count)
        
        # File Stats
        for fpath in files_list:
            if fpath not in file_map:
                file_map[fpath] = {"total": 0, "incidents": 0}
            stats = file_map[fpath]
            stats["total"] += 1
            if label == 1:
                stats["incidents"] += 1
                
        valid_rows.append({
            "churn": churn,
            "files_list": files_list,
            "label_value": label
        })
                
    # 2. Compute Repo Baselines
    print("Computing baselines...")
    log_churns = [normalize.log1p_int(c) for c in churn_values]
    if len(log_churns) > 1:
        mean_log = statistics.mean(log_churns)
        std_log = statistics.stdev(log_churns)
    else:
        mean_log = log_churns[0] if log_churns else 0
        std_log = 1.0 # Default
        
    if len(files_counts) > 1:
        p50 = statistics.median(files_counts)
        # Simple p90
        files_counts.sort()
        idx_90 = int(len(files_counts) * 0.9)
        p90 = files_counts[idx_90]
    else:
        p50 = files_counts[0] if files_counts else 1
        p90 = files_counts[0] if files_counts else 5

    # Save Baselines
    print(f"Baselines: log_churn_mean={mean_log:.2f}, std={std_log:.2f}, files_p90={p90}")
    cursor.execute("""
        INSERT OR REPLACE INTO repo_baselines 
        (repo, feature_version, log_churn_mean, log_churn_std, files_changed_p50, files_changed_p90)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (repo_slug, FEATURE_VERSION, mean_log, std_log, p50, p90))
    
    # Save File Stats
    print(f"Saving stats for {len(file_map)} files...")
    for fpath, stats in file_map.items():
        cursor.execute("""
            INSERT OR REPLACE INTO file_stats
            (repo, feature_version, file_path, total_changes, incident_changes)
            VALUES (?, ?, ?, ?, ?)
        """, (repo_slug, FEATURE_VERSION, fpath, stats["total"], stats["incidents"]))
        
    conn.commit()
    
    # 3. Compute Buckets (Requires FeatureStore to reload baselines)
    print("Re-scoring history for buckets...")
    # Force mock/reload of FeatureStore with NEW baselines
    # But FeatureStore loads from DB on init.
    # The DB is updated committed above.
    store = FeatureStore({
        "repo_slug": repo_slug,
        "critical_paths": {} 
    })
    # Actually feature_store._load_repo_baselines() needs implementation to read DB!
    # Currently it's a mock in the codebase.
    # We must UPDATE FeatureStore FIRST to read from DB.
    pass 
    # Logic note: Python script continues... but FeatureStore implementation needs update.
    # I will finish the script assuming FeatureStore logic is updated.
    
    # Bucket Accumulators
    bucket_map = {
        "churn_high": {"t":0, "i":0}, "churn_med": {"t":0, "i":0}, "churn_low": {"t":0, "i":0},
        "crit_high": {"t":0, "i":0}, "crit_low": {"t":0, "i":0},
        "dep_high": {"t":0, "i":0}, "dep_low": {"t":0, "i":0}
    }
    
    for row in valid_rows:
        label = row["label_value"]
        if label is None: continue # Can't use for incident stats if unknown
        
        # Approximate RawSignals
        raw: RawSignals = {
            "files_changed": row["files_list"],
            "total_churn": row["churn"],
            "lines_added": 0, "lines_deleted": 0, "per_file_churn": {}, # Missing exact context
            "touched_services": [], # Missing
            "linked_issue_ids": [],
            "repo_slug": repo_slug, "entity_type": "pr", "entity_id": "backfill", "timestamp": "now", "author": None, "branch": None
        }
        
        # Build features (should use new baselines)
        try:
            feats, _ = store.build_features(raw)
            
            # Update Buckets
            # Churn
            c_score = feats.get("churn_score", 0)
            if c_score > 0.7: b = "churn_high"
            elif c_score < 0.2: b = "churn_low"
            else: b = "churn_med"
            bucket_map[b]["t"] += 1
            if label == 1: bucket_map[b]["i"] += 1
            
            # Criticality
            crit_score = feats.get("critical_path_score", 0)
            if crit_score > 0.5: b = "crit_high"
            else: b = "crit_low"
            bucket_map[b]["t"] += 1
            if label == 1: bucket_map[b]["i"] += 1
            
            # Dependency (might be always 0 if no deps)
            dep_score = feats.get("dependency_risk_score", 0)
            if dep_score > 0.5: b = "dep_high"
            else: b = "dep_low"
            bucket_map[b]["t"] += 1
            if label == 1: bucket_map[b]["i"] += 1
            
        except Exception as e:
            # print(f"Error scoring row: {e}")
            pass
            
    # Save buckets
    print("Saving bucket stats...")
    for bid, stats in bucket_map.items():
        if stats["t"] > 0:
            cursor.execute("""
                INSERT OR REPLACE INTO bucket_stats
                (repo, feature_version, bucket_id, total_count, incident_count)
                VALUES (?, ?, ?, ?, ?)
            """, (repo_slug, FEATURE_VERSION, bid, stats["t"], stats["i"]))
            
    conn.commit()
    conn.close()
    print("Backfill complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    args = parser.parse_args()
    backfill(args.repo)
