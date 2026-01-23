import sqlite3
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from riskbot.config import RISK_DB_PATH

def rebuild_file_stats(repo):
    print(f"Rebuilding file_stats for {repo}...")
    
    if not os.path.exists(RISK_DB_PATH):
        print(f"Error: DB not found at {RISK_DB_PATH}")
        return

    conn = sqlite3.connect(RISK_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Clear existing stats for this repo (full rebuild)
    cursor.execute("DELETE FROM file_stats WHERE repo = ?", (repo,))
    print(f"Cleared existing stats. Processing runs...")
    
    # 2. Fetch all runs
    cursor.execute("""
        SELECT files_json, label_value, feature_version 
        FROM pr_runs 
        WHERE repo = ? AND files_json IS NOT NULL
    """, (repo,))
    
    rows = cursor.fetchall()
    
    # 3. Aggregate
    # keyed by (file_path, feature_version)
    stats = defaultdict(lambda: {"total_changes": 0, "incident_changes": 0})
    
    count = 0
    for row in rows:
        try:
            files = json.loads(row['files_json'])
            is_incident = 1 if row['label_value'] == 1 else 0
            version = row['feature_version'] or 'v1'
            
            # Allow dict or list format
            if isinstance(files, dict):
                file_list = files.keys()
            elif isinstance(files, list):
                file_list = files
            else:
                continue
                
            for f in file_list:
                key = (f, version)
                stats[key]["total_changes"] += 1
                stats[key]["incident_changes"] += is_incident
            
            count += 1
        except Exception as e:
            continue
            
    print(f"Processed {count} runs. Writing {len(stats)} file records...")
    
    # 4. Write to DB
    cursor.executemany("""
        INSERT INTO file_stats (repo, feature_version, file_path, total_changes, incident_changes, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, [
        (repo, ver, path, d["total_changes"], d["incident_changes"])
        for (path, ver), d in stats.items()
    ])
    
    conn.commit()
    conn.close()
    print("Done!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 rebuild_file_stats.py <owner/repo>")
        sys.exit(1)
        
    rebuild_file_stats(sys.argv[1])
