import sqlite3
import os
from releasegate.config import DB_PATH

def ensure_schema(conn):
    """
    Ensures the audit table exists.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_decisions (
            decision_id TEXT PRIMARY KEY,
            context_id TEXT,
            repo TEXT,
            pr_number INTEGER,
            release_status TEXT,
            policy_bundle_hash TEXT,
            engine_version TEXT,
            decision_hash TEXT NOT NULL,
            full_decision_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            evaluation_key TEXT UNIQUE
        )
    """)
    # Indices for performance
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_repo_pr ON audit_decisions(repo, pr_number)")
    # evaluation_key is implied index by UNIQUE constraint usually, but explicit index doesn't hurt if engine doesn't auto-create (sqlite usually does for unique)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_decisions(created_at)")
    conn.commit()

def get_connection():
    """
    Returns a connection to the SQLite DB, ensuring schema exists.
    """
    # Ensure directory exists
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        
    conn = sqlite3.connect(DB_PATH)
    
    # Enable Row factory for easier access if desired, but existing code uses tuples mostly?
    # Reader uses row access.
    conn.row_factory = sqlite3.Row
    
    ensure_schema(conn)
    return conn
