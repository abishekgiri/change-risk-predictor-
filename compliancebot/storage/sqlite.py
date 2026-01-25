import sqlite3
import json
import os
from compliancebot.config import DB_PATH, JSONL_PATH
from compliancebot.storage.schema import init_db

def save_run(repo, pr_number, base_sha, head_sha, score_data, features):
    init_db()
    
    risk_score = score_data["risk_score"]
    risk_level = score_data["risk_level"]
    reasons_json = json.dumps(score_data["reasons"])
    features_json = json.dumps(features)
    
    # 2. Writes to SQLite
    try:
        conn = sqlite3.connect(DB_PATH)
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
        print(f"Saved run to DB: {DB_PATH}")
    except Exception as e:
        print(f"Error saving to SQLite: {e}")

    # 3. Write to JSONL
    try:
        run_data = {
            "repo": repo,
            "pr": pr_number,
            "base": base_sha,
            "head": head_sha,
            "score": risk_score,
            "level": risk_level,
            "reasons": score_data["reasons"],
            "features": features,
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "attempt": os.getenv("GITHUB_RUN_ATTEMPT")
        }
        
        with open(JSONL_PATH, "a") as f:
            f.write(json.dumps(run_data) + "\n")
            f.flush()
            os.fsync(f.fileno())
        
        print(f"Appended run to JSONL: {JSONL_PATH}")
    except Exception as e:
        print(f"Error saving to JSONL: {e}")

def add_label(repo: str, pr_number: int, label_type: str, severity: int = None):
    """Add a label to a PR."""
    init_db()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    INSERT INTO pr_labels (repo, pr_number, label_type, severity)
    VALUES (?, ?, ?, ?)
    """, (repo, pr_number, label_type, severity))
    
    conn.commit()
    conn.close()

