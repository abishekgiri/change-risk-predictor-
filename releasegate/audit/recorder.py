import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from releasegate.config import DB_PATH
from releasegate.decision.types import Decision

class AuditRecorder:
    """
    Writes decisions to the immutable audit log.
    Enforces hashing and integrity.
    """
    
    ENGINE_VERSION = "0.1.0" # Should come from package

    @staticmethod
    def record(decision: Decision):
        # 1. Canonical Serialization (Sort keys for stable hash)
        # Pydantic's model_dump_json doesn't guarantee key order by default in all versions reliably for hashing
        # So we verify or re-dump.
        # Actually pydantic v2 is usually good, but let's be safe: load -> dump with sort_keys=True
        
        raw_dict = decision.model_dump(mode='json')
        canonical_json = json.dumps(raw_dict, sort_keys=True, ensure_ascii=False)
        
        # 2. Compute Integrity Hash
        decision_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        
        # 3. Insert (Insert Only - No Update)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # We assume pr_number might be available via Context linkage or we extract from decision if we added it?
        # The schema asks for repo/pr_number. The Decision object has `context_id`. 
        # We might need to join or assume the caller passed context, OR we embedded repo/pr in Decision.
        # Looking at Decision model: it has context_id, but not explicit repo/pr. 
        # However, the `change` object in Context has them.
        # BUT `record` only takes `Decision`.
        # Strategy: The Decision JSON contains everything. For top-level columns (repo/pr), 
        # we might need to query context or just store NULL if not easily available, 
        # OR we parse the decision JSON if we stored context snapshot inside it? 
        # Wait, the CLI lists "repo/pr". 
        # Let's peek at Decision.context_id -> we assume we can't look up context from just ID easily if context isn't persisted.
        # Correction: We didn't implement Context persistence yet (only Audit).
        # FIX: We should extract repo/pr from the `Change` object if we had access to it.
        # The CLI has `ctx` and `decision`.
        # Updating `record` signature to take `EvaluationContext` optionally, or just extracting from decision if it has it.
        # Decision has `matched_policies` etc.
        # Let's update `record` to take `EvaluationContext` as well to populate the index columns.
        pass

    @staticmethod
    def record_with_context(decision: Decision, repo: str, pr_number: int):
        # 1. Canonical Serialization
        raw_dict = decision.model_dump(mode='json')
        canonical_json = json.dumps(raw_dict, sort_keys=True, ensure_ascii=False)
        
        # 2. Compute Integrity Hash
        decision_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        
        # 3. Insert
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO audit_decisions (
                    decision_id, context_id, repo, pr_number, 
                    release_status, policy_bundle_hash, engine_version, 
                    decision_hash, full_decision_json, created_at, evaluation_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                decision.decision_id,
                decision.context_id,
                repo,
                pr_number,
                decision.release_status,
                decision.policy_bundle_hash,
                AuditRecorder.ENGINE_VERSION,
                decision_hash,
                canonical_json,
                decision.timestamp.isoformat(),
                decision.evaluation_key
            ))
            conn.commit()
            return decision

        except sqlite3.IntegrityError as e:
            # Idempotency: evaluation_key already exists -> fetch existing row
            if "audit_decisions.evaluation_key" in str(e) or "evaluation_key" in str(e):
                cursor.execute("""
                    SELECT full_decision_json
                    FROM audit_decisions
                    WHERE evaluation_key = ?
                    LIMIT 1
                """, (decision.evaluation_key,))
                row = cursor.fetchone()
                if row and row[0]:
                    existing = row[0]
                    if isinstance(existing, str):
                        existing = json.loads(existing)
                    return Decision.model_validate(existing)
            raise
        finally:
            conn.close()
