import sqlite3
import json
import random
import os
import sys

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riskbot.config import RISK_DB_PATH
from riskbot.storage.schema import init_db

def seed():
    print(f"Seeding database at {RISK_DB_PATH}...")
    init_db()
    conn = sqlite3.connect(RISK_DB_PATH)
    cursor = conn.cursor()
    
    # Synthetic Data: 5 Safe PRs, 5 Risky PRs
    data = []
    
    # Generate Safe PRs
    for i in range(101, 106):
        features = {
            "diff": {"files_changed": 2, "loc_added": 10, "loc_deleted": 5},
            "files": ["readme.md", "docs/index.md"],
            "tests": True,
            "paths": [],
            "churn": {"hotspots": []},
            "metadata": {"title": "Doc update", "author": "dev-1"}
        }
        data.append({
            "repo": "seed-repo", "pr": i, "score": 10, "level": "LOW",
            "features": features, "label": "safe"
        })

    # Generate Risky PRs
    for i in range(201, 206):
        features = {
            "diff": {"files_changed": 15, "loc_added": 500, "loc_deleted": 100},
            "files": ["auth/login.py", "db/schema.sql", "api/v1/user.py"],
            "texts": False,
            "paths": ["auth/", "db/", "api/v1/"],
            "churn": {"hotspots": ["auth/login.py"]}, # High churn file
            "metadata": {"title": "Refactor auth", "author": "dev-2"}
        }
        data.append({
            "repo": "seed-repo", "pr": i, "score": 85, "level": "HIGH",
            "features": features, "label": "incident"
        })

    # Insert
    for item in data:
        # Run
        cursor.execute("""
            INSERT OR IGNORE INTO pr_runs 
            (repo, pr_number, base_sha, head_sha, risk_score, risk_level, reasons_json, features_json, created_at)
            VALUES (?, ?, 'base', 'head', ?, ?, '[]', ?, datetime('now'))
        """, (item['repo'], item['pr'], item['score'], item['level'], json.dumps(item['features'])))
        
        # Label
        cursor.execute("""
            INSERT OR IGNORE INTO pr_labels (repo, pr_number, label_type)
            VALUES (?, ?, ?)
        """, (item['repo'], item['pr'], item['label']))

    conn.commit()
    conn.close()
    print("✅ Seeded 10 labeled PRs. You can now Train the model in the Dashboard.")

if __name__ == "__main__":
    seed()
