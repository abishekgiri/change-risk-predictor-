import sqlite3
import json
from typing import List, Optional, Dict, Any
from releasegate.config import DB_PATH

class AuditReader:
    """
    Read-only access to audit logs.
    """
    
    @staticmethod
    def list_decisions(repo: str, limit: int = 20, status: Optional[str] = None, pr: Optional[int] = None) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM audit_decisions WHERE repo = ?"
        params = [repo]
        
        if status:
            query += " AND release_status = ?"
            params.append(status)
            
        if pr:
            query += " AND pr_number = ?"
            params.append(pr)
            
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(r) for r in rows]

    @staticmethod
    def get_decision(decision_id: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM audit_decisions WHERE decision_id = ?", (decision_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            d = dict(row)
            # Parse JSON for convenience if the caller wants it, or keep it strict. 
            # Let's return raw dictionary but maybe parse the full_decision_json if requested?
            # For now return DB columns.
            return d
        return None

    @staticmethod
    def get_decision_by_evaluation_key(evaluation_key: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM audit_decisions WHERE evaluation_key = ?", (evaluation_key,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
