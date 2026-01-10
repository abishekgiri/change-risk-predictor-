import sqlite3
import os
from riskbot.config import RISK_DB_PATH

def init_db():
    os.makedirs(os.path.dirname(RISK_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(RISK_DB_PATH)
    cursor = conn.cursor()
    
    # Runs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pr_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        base_sha TEXT NOT NULL,
        head_sha TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        risk_score INTEGER,
        risk_level TEXT,
        reasons_json TEXT,
        features_json TEXT,
        github_run_id TEXT,
        github_run_attempt INTEGER,
        schema_version INTEGER DEFAULT 1,
        UNIQUE(repo, pr_number, head_sha)
    )
    """)
    
    # Labels Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pr_labels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo TEXT,
        pr_number INTEGER,
        label_type TEXT,
        severity INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(repo, pr_number) REFERENCES pr_runs(repo, pr_number)
    )
    """)
    
    # Index for fast lookup by PR
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_pr_runs_repo_pr ON pr_runs(repo, pr_number)
    """)
    
    conn.commit()
    conn.close()
