import sqlite3
import os
from releasegate.config import DB_PATH

# Production Schema Version
# Increment this if you change columns to force re-ingestion compatibility checks
SCHEMA_VERSION = "v1"

def init_db():
    """
    Initialize the SQLite database with the production-grade schema.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. PR Runs Table (The centralized feature store)
    # We added explicit columns for scoring factors to ensure fast, deterministic queries.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pr_runs (
        run_id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        base_sha TEXT,
        head_sha TEXT,
        
        -- Risk Outputs
        risk_score INTEGER, -- 0-100
        risk_level TEXT, -- LOW/MED/HIGH
        risk_probability FLOAT, -- 0.0-1.0 (Calibrated)
        
        -- Feature Vector (Frozen V1 Schema)
        feature_version TEXT DEFAULT 'v1',
        files_touched INTEGER DEFAULT 0,
        files_json TEXT, -- Phase 6: Full file list for criticality
        churn INTEGER DEFAULT 0,
        entropy FLOAT DEFAULT 0.0,
        
        -- Criticality & Impact
        critical_files_count INTEGER DEFAULT 0,
        criticality_tier INTEGER DEFAULT 0,
        blast_radius INTEGER DEFAULT 0,
        
        -- History signals
        hotspot_score FLOAT DEFAULT 0.0, -- 0.0-1.0 percentile
        
        -- Labels (Phase 3A - Ground Truth)
        label_value INTEGER, -- 1 (Risky), 0 (Safe), NULL (Unknown)
        label_source TEXT, -- 'github_label', 'revert_chain', 'keyword'
        label_confidence FLOAT, -- 0.0 - 1.0
        label_tags TEXT, -- JSON list ["bug", "sev1"]
        label_reason TEXT, -- Human readable reason
        label_sources TEXT, -- JSON detailed provenance
        label_updated_at TIMESTAMP,
        label_version TEXT, -- e.g. "v2"
    
        -- Entity Linking
        entity_type TEXT DEFAULT 'commit', -- 'commit' or 'pr'
        entity_id TEXT, -- sha or pr_number
        linked_pr TEXT, -- Associated PR number if entity is commit
        linked_issue_ids TEXT, -- JSON list of linked issues
        
        -- Raw JSONs for debugging/re-scoring
        reasons_json TEXT,
        features_json TEXT,
        
        -- Metadata
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        github_run_id TEXT,
        github_run_attempt TEXT,
        schema_version INTEGER DEFAULT 2,
        
        UNIQUE(repo, pr_number, head_sha)
    )
    """)
    
    # 2. Labels Table (Ground Truth - simplified view still useful)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pr_labels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        label_type TEXT NOT NULL, -- 'incident', 'rollback', 'safe', 'hotfix'
        severity INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(repo, pr_number, label_type)
    )
    """)
    
    # 3. GitHub API Cache (Prevent Rate Limits)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS github_cache (
        cache_key TEXT PRIMARY KEY, -- "issue:123", "pr:45"
        response_json TEXT,
        etag TEXT,
        fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # 4. GitLab API Cache
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS gitlab_cache (
        cache_key TEXT PRIMARY KEY, -- "issue:123", "mr:45"
        response_json TEXT,
        fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # 5. Repo Baselines (Phase 7: Enterprise Hardening)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS repo_baselines (
        repo TEXT NOT NULL,
        feature_version TEXT NOT NULL,
        log_churn_mean FLOAT,
        log_churn_std FLOAT,
        files_changed_p50 FLOAT,
        files_changed_p90 FLOAT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (repo, feature_version)
    )
    """)
    
    # 6. File Statistics (Empirical File Risk)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_stats (
        repo TEXT NOT NULL,
        feature_version TEXT NOT NULL,
        file_path TEXT NOT NULL,
        total_changes INTEGER DEFAULT 0,
        incident_changes INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (repo, feature_version, file_path)
    )
    """)

    # 7. Bucket Statistics (Empirical Pattern Risk)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS bucket_stats (
        repo TEXT NOT NULL,
        feature_version TEXT NOT NULL,
        bucket_id TEXT NOT NULL, -- e.g. "churn_high", "crit_low"
        total_count INTEGER DEFAULT 0,
        incident_count INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (repo, feature_version, bucket_id)
    )
    """)
    
    # 8. Enforcement Events (Idempotency & Audit)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS enforcement_events (
        idempotency_key TEXT PRIMARY KEY,
        decision_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL, -- SUCCESS, FAILED, SKIPPED
        detail TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 9. Audit Log (Immutable, Hashed)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_decisions (
        decision_id TEXT PRIMARY KEY,
        context_id TEXT NOT NULL,
        repo TEXT NOT NULL,
        pr_number INTEGER,
        release_status TEXT NOT NULL,
        policy_bundle_hash TEXT NOT NULL,
        engine_version TEXT NOT NULL,
        decision_hash TEXT NOT NULL, -- SHA256 of canonical JSON
        full_decision_json TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL, -- ISO UTC
        evaluation_key TEXT -- Idempotency key for the evaluation itself
    )
    """)
    
    # Audit Indexes for Reporting
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_context_id ON audit_decisions(context_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_repo_created ON audit_decisions(repo, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_repo_pr ON audit_decisions(repo, pr_number, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_status_created ON audit_decisions(release_status, created_at)")
    
    # Unique Index for Evaluation Idempotency
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_evaluation_key ON audit_decisions(evaluation_key)")

    # Trigger: Prevent Updates (Immutability)
    cursor.execute("""
    CREATE TRIGGER IF NOT EXISTS prevent_audit_update
    BEFORE UPDATE ON audit_decisions
    BEGIN
        SELECT RAISE(FAIL, 'Audit logs are immutable: UPDATE not allowed');
    END;
    """)

    # Trigger: Prevent Deletes (Immutability)
    cursor.execute("""
    CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
    BEFORE DELETE ON audit_decisions
    BEGIN
        SELECT RAISE(FAIL, 'Audit logs are immutable: DELETE not allowed');
    END;
    """)

    conn.commit()
    conn.close()
