import sqlite3
import json
import os
from datetime import datetime
from riskbot.config import RISK_DB_PATH, RISK_JSONL_PATH
from riskbot.storage.schema import init_db

def save_run(
    repo: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    score_data: dict,
    features: dict
):
    """Save the run data to SQLite and JSONL."""
    
    # 1. Ensure DB exists
    init_db()
    
    # Prepare data
    risk_score = score_data["score"]
    risk_level = score_data["risk_level"]
    reasons_json = json.dumps(score_data["reasons"])
    features_json = json.dumps(features)
    
    
    # 2. Writes to SQLite
    try:
        conn = sqlite3.connect(RISK_DB_PATH)
        cursor = conn.cursor()
        
        # Metadata from Environment
        github_run_id = os.getenv("GITHUB_RUN_ID")
        github_run_attempt = os.getenv("GITHUB_RUN_ATTEMPT")
        
        cursor.execute("""
            INSERT OR IGNORE INTO pr_runs 
            (repo, pr_number, base_sha, head_sha, risk_score, risk_level, reasons_json, features_json, github_run_id, github_run_attempt, schema_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (repo, pr_number, base_sha, head_sha, risk_score, risk_level, reasons_json, features_json, github_run_id, github_run_attempt))
        
        conn.commit()
        conn.close()
        print(f"Saved run to DB: {RISK_DB_PATH}")
    except Exception as e:
        print(f"Error saving to SQLite: {e}")

    # 3. Write to JSONL (Redundancy / Training Set)
    try:
        os.makedirs(os.path.dirname(RISK_JSONL_PATH), exist_ok=True)
        record = {
            "timestamp": datetime.now().isoformat(),
            "repo": repo,
            "pr_number": pr_number,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "score_data": score_data,
            "features": features
        }
        with open(RISK_JSONL_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
        print(f"Appended run to JSONL: {RISK_JSONL_PATH}")
    except Exception as e:
        print(f"Error saving to JSONL: {e}")

def add_label(repo: str, pr_number: int, label_type: str, severity: int = None):
    """Add a label to a PR."""
    init_db()
    
    conn = sqlite3.connect(RISK_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO pr_labels (repo, pr_number, label_type, severity)
        VALUES (?, ?, ?, ?)
    """, (repo, pr_number, label_type, severity))
    
    conn.commit()
    conn.close()
