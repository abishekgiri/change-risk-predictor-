import sqlite3
from riskbot.config import RISK_DB_PATH
import os

def init_db():
    """Initialize the SQLite database and create tables if they don't exist."""
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(RISK_DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(RISK_DB_PATH)
    cursor = conn.cursor()
    
    # Validation Run Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pr_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo TEXT,
        pr_number INTEGER,
        base_sha TEXT,
        head_sha TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        risk_score INTEGER,
        risk_level TEXT,
        reasons_json TEXT,
        features_json TEXT
    )
    """)
    
    # Index for fast lookup by PR
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_pr_runs_repo_pr ON pr_runs(repo, pr_number)
    """)
    
    conn.commit()
    conn.close()
