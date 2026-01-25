import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List
from compliancebot.config import DB_PATH
from compliancebot.features import normalize
import math

def aggregate_file_risks(repo: str, window_days: int = 90) -> Dict[str, Dict]:
    """
    Aggregate file-level risk signals from existing data.
    
    Args:
        repo: Repository slug
        window_days: Time window for recent churn calculation
    
    Returns:
        Dict mapping file_path -> aggregated signals
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Calculate cutoff for "recent"
    cutoff_date = (datetime.now() - timedelta(days=window_days)).isoformat()
    
    file_data = {}
    
    # Query: Get all commits/PRs with files and labels
    # We need: file, churn, label, timestamp
    # Schema: pr_runs has files_json, churn, label_value, timestamp
    
    cursor.execute("""
    SELECT files_json, churn, label_value, created_at
    FROM pr_runs
    WHERE repo = ?
    AND files_json IS NOT NULL
    """, (repo,))
    
    rows = cursor.fetchall()
    
    for row in rows:
        try:
            import json
            files_data = json.loads(row['files_json']) if row['files_json'] else []
            churn = row['churn'] or 0
            label = row['label_value'] # 1 = incident, 0 = safe, NULL = unknown
            timestamp = row['created_at']
            
            # Parse files (format may vary, handle gracefully)
            if isinstance(files_data, list):
                files = files_data
            elif isinstance(files_data, dict):
                files = list(files_data.keys())
            else:
                continue
            
            for file_path in files:
                if file_path not in file_data:
                    file_data[file_path] = {
                        "changes": 0,
                        "incidents": 0,
                        "total_churn": 0,
                        "recent_churn": 0,
                        "last_touched": timestamp
                    }
                
                fd = file_data[file_path]
                fd["changes"] += 1
                
                if label == 1:
                    fd["incidents"] += 1
                
                # Churn (distribute evenly across files for simplicity)
                file_churn = churn / len(files) if files else 0
                fd["total_churn"] += file_churn
                
                if timestamp and timestamp >= cutoff_date:
                    fd["recent_churn"] += file_churn
                
                # Track latest touch
                if timestamp and (not fd["last_touched"] or timestamp > fd["last_touched"]):
                    fd["last_touched"] = timestamp
        
        except Exception as e:
            print(f"Error processing row: {e}")
            continue
    
    conn.close()
    
    # Post-process: Laplace smoothing and normalization
    alpha = 1.0
    all_churn_values = [fd["total_churn"] for fd in file_data.values() if fd["total_churn"] > 0]
    
    for file_path, fd in file_data.items():
        # Laplace smoothed incident rate
        fd["incident_rate"] = (fd["incidents"] + alpha) / (fd["changes"] + 2 * alpha)
        
        # Normalize churn (reuse Phase 6 logic)
        if all_churn_values:
            # Z-score then minmax
            log_churn = math.log1p(fd["total_churn"])
            mean_log = sum(math.log1p(c) for c in all_churn_values) / len(all_churn_values)
            std_log = math.sqrt(sum((math.log1p(c) - mean_log)**2 for c in all_churn_values) / len(all_churn_values))
            
            if std_log > 0:
                z = (log_churn - mean_log) / std_log
                # Minmax to 0-1
                fd["churn_score"] = normalize.minmax(z, -3, 3)
            else:
                fd["churn_score"] = 0.0
        else:
            fd["churn_score"] = 0.0
    
    return file_data
