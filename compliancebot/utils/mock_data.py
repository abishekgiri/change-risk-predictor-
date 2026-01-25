import sqlite3
import json
import random
import uuid
from datetime import datetime, timedelta
from compliancebot.config import DB_PATH
import os

def generate_mock_data(n=60):
    """
    Generates n mock PR runs and labels them.
    Target: ~20% distribution of 'high risk' (incident/rollback) to make the model learn something.
    """
    print(f"Generating {n} mock PR runs...")
    
    # Ensure DB exists
    if not os.path.exists(DB_PATH):
        # Fallback if config path isn't absolute or initialized
        print(f"Warning: DB at {DB_PATH} not found. Creating new...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create tables if they don't exist (just in case this runs before app)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pr_runs (
        repo TEXT,
        pr_number INTEGER,
        base_sha TEXT,
        head_sha TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        features_json TEXT,
        created_at TEXT,
        PRIMARY KEY (repo, pr_number)
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pr_labels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo TEXT,
        pr_number INTEGER,
        label_type TEXT,
        severity INTEGER,
        created_at TEXT
    )
    """)
    
    # Repos to simulate
    repos = ["myorg/payment-service", "myorg/auth-service", "myorg/frontend-monorepo"]
    
    for i in range(n):
        repo = random.choice(repos)
        pr_number = 1000 + i
        base_sha = f"base{i}"
        head_sha = f"head{i}"
        
        # Simulate features
        # We want some correlation so the model actually "learns"
        # If is_risky, make it larger and touch critical paths
        is_risky = random.random() < 0.2
        
        lines_changed = random.randint(500, 2000) if is_risky else random.randint(10, 200)
        files_count = random.randint(10, 50) if is_risky else random.randint(1, 5)
        has_tests = False if (is_risky and random.random() < 0.5) else True
        critical_touched = ["configs", "auth"] if is_risky else []
        
        features = {
            "diff": {
                "files_changed": files_count,
                "loc_added": lines_changed,
                "loc_deleted": lines_changed // 2
            },
            "files": [f"file_{j}.py" for j in range(files_count)],
            "churn": {
                "hotspots": ["auth.py"] if random.random() < 0.3 else []
            },
            "paths": critical_touched,
            "tests": has_tests
        }
        
        # Insert Run
        cursor.execute("""
        INSERT OR IGNORE INTO pr_runs 
        (repo, pr_number, base_sha, head_sha, risk_score, risk_level, features_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            repo, 
            pr_number, 
            base_sha, 
            head_sha, 
            80 if is_risky else 10, 
            "HIGH" if is_risky else "LOW",
            json.dumps(features),
            (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
        ))
        
        # Insert Label
        # Label types: safe, hotfix, incident, rollback
        if is_risky:
            label_type = "incident" if random.random() < 0.7 else "rollback"
            severity = 5
        else:
            label_type = "safe"
            severity = 0
        
        cursor.execute("""
        INSERT OR IGNORE INTO pr_labels (repo, pr_number, label_type, severity, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (repo, pr_number, label_type, severity, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    print(f"Successfully added {n} mock records to {DB_PATH}")

if __name__ == "__main__":
    generate_mock_data()
