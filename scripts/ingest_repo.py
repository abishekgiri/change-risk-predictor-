import sys
import os
import yaml
import json
import sqlite3
from datetime import datetime

# Add project root to python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riskbot.ingestion.git_ingest import GitIngest
from riskbot.ingestion.dependency_graph import DependencyGraph
from riskbot.storage.schema import init_db
from riskbot.config import RISK_DB_PATH

# Phase 3B Providers & Labelers
from riskbot.ingestion.providers.github_provider import GitHubProvider
from riskbot.ingestion.labeling.base import LabelResult
from riskbot.ingestion.labeling.metadata_labeler import MetadataLabeler
from riskbot.ingestion.labeling.revert_labeler import RevertLabeler
from riskbot.ingestion.labeling.hotfix_labeler import HotfixLabeler
from riskbot.ingestion.labeling.unifier import LabelUnifier

def load_config():
    with open("riskbot.yaml", "r") as f:
        return yaml.safe_load(f)

def ingest_history(repo_path=".", limit=1000):
    print(f"🚀 Starting Ingestion (Phase 3B) for {repo_path} (limit={limit})...")
    
    # 1. Config & Check
    config = load_config()
    min_conf = config.get("labeling", {}).get("min_high_confidence", 0.85)

    # 2. Initialize DB & Components
    print(f"DEBUG: Using DB Path: {os.path.abspath(RISK_DB_PATH)}")
    init_db()
    conn = sqlite3.connect(RISK_DB_PATH)
    cursor = conn.cursor()
    
    ingestor = GitIngest(repo_path)
    dg = DependencyGraph("service_graph.yaml")
    
    # Providers & Labelers
    # Default to GitHub for now (can add logic to choose provider based on config)
    # provider_name = config.get("provider", "github")
    git_provider = GitHubProvider(config)
    
    gh_labeler = MetadataLabeler(config, git_provider) # Replaces old GitHubLabeler
    rv_labeler = RevertLabeler(config)
    hf_labeler = HotfixLabeler(config)
    unifier = LabelUnifier(min_conf)
    
    # 3. Ingest History
    df = ingestor.get_commit_history(limit=limit)
    print(f"📥 Extracted {len(df)} commits.")
    
    # Hotspot Calc
    hotspots = ingestor.analyze_hotspots(df, top_n=50)
    max_churn = hotspots.max() if not hotspots.empty else 1
    
    def get_hotspot_score(files):
        scores = [hotspots.get(f, 0) / max_churn for f in files]
        return max(scores) if scores else 0.0

    count = 0
    for _, row in df.iterrows():
        files = row['files_json']
        churn = row['lines_added'] + row['lines_deleted']
        
        # 4. Multi-Source Labeling
        # Construct generic entity wrapper (Schema 3A)
        # For MVP: 'linked_issues' is heuristic extraction from message (e.g. #123)
        if "revert" in row["message"].lower():
             # Basic Revert detection
             pass
        
        # Parse References (GitHub #123, GitLab !45)
        import re
        linked_refs = []
        
        # Issues (#123)
        for issue_id in re.findall(r"#(\d+)", row["message"]):
            linked_refs.append({"type": "issue", "id": issue_id})
            
        # GitLab MRs (!45)
        for mr_id in re.findall(r"!(\d+)", row["message"]):
            linked_refs.append({"type": "mr", "id": mr_id})
        
        entity = {
            "type": "commit",
            "id": row["hexsha"],
            "message": row["message"],
            "branches": [], 
            "linked_issues": linked_refs, # Now list of dicts
            "reverted_by_sha": None # Needs lookahead or pre-processing
        }
        
        results = [
            gh_labeler.label(entity),
            rv_labeler.label(entity),
            hf_labeler.label(entity)
        ]
        
        final_label = unifier.unify(results)
        
        # 5. Features
        impact = dg.get_downstream_impact(files)
        blast_radius = impact['blast_radius_score']
        hotspot_score = get_hotspot_score(files)
        entropy = min(len(files) / 10.0, 1.0)
        critical_count = 1 if row['is_critical'] else 0
        
        # 6. Insert (Phase 3A Schema)
        cursor.execute("""
            INSERT OR IGNORE INTO pr_runs 
            (
                repo, pr_number, base_sha, head_sha,
                files_touched, files_json, churn, entropy,
                critical_files_count, criticality_tier, blast_radius,
                hotspot_score, 
                
                label_value, label_source, label_confidence,
                label_tags, label_reason, label_sources,
                label_updated_at, label_version,
                
                entity_type, entity_id, linked_issue_ids,
                
                reasons_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            config["github"]["repo"], 
            0, # Historical
            row['hexsha'] + "^", 
            row['hexsha'],
            
            len(files), json.dumps(files), churn, entropy,
            critical_count, 0, blast_radius,
            hotspot_score,
            
            # Label Data
            final_label.value, 
            final_label.source, 
            final_label.confidence,
            json.dumps(final_label.tags),
            final_label.reason,
            json.dumps([{"source": r.source, "conf": r.confidence} for r in results]),
            datetime.utcnow().isoformat(),
            "v2",
            
            "commit", row['hexsha'], json.dumps(linked_refs),
            
            "[]", row['date'].isoformat()
        ))
        
        count += 1
        
    conn.commit()
    conn.close()
    print(f"✅ Ingested {count} rows with Phase 3A Labels into {RISK_DB_PATH}")

if __name__ == "__main__":
    ingest_history()
