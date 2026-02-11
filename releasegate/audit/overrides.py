import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db


def _get_last_hash(repo: str) -> Optional[str]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT event_hash FROM audit_overrides WHERE repo = ? ORDER BY created_at DESC LIMIT 1",
        (repo,)
    )
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def record_override(
    repo: str,
    pr_number: Optional[int] = None,
    issue_key: Optional[str] = None,
    decision_id: Optional[str] = None,
    actor: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Append-only override ledger record with hash chaining.
    """
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    prev_hash = _get_last_hash(repo) or "0" * 64

    payload = {
        "repo": repo,
        "pr_number": pr_number,
        "issue_key": issue_key,
        "decision_id": decision_id,
        "actor": actor,
        "reason": reason,
        "previous_hash": prev_hash,
        "created_at": now,
    }
    event_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    override_id = hashlib.sha256(f"{repo}:{now}:{event_hash}".encode()).hexdigest()[:32]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO audit_overrides (
            override_id, decision_id, repo, pr_number, issue_key, actor, reason, previous_hash, event_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            override_id,
            decision_id,
            repo,
            pr_number,
            issue_key,
            actor,
            reason,
            prev_hash,
            event_hash,
            now,
        ),
    )
    conn.commit()
    conn.close()

    payload["override_id"] = override_id
    payload["event_hash"] = event_hash
    return payload


def list_overrides(repo: str, limit: int = 200, pr: Optional[int] = None) -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    query = "SELECT * FROM audit_overrides WHERE repo = ?"
    params = [repo]
    if pr is not None:
        query += " AND pr_number = ?"
        params.append(pr)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def verify_override_chain(repo: str, pr: Optional[int] = None) -> Dict[str, Any]:
    """
    Verify override hash-chain integrity for a repo (optionally for one PR).
    """
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT override_id, decision_id, repo, pr_number, issue_key, actor, reason, previous_hash, event_hash, created_at
        FROM audit_overrides
        WHERE repo = ?
    """
    params: List[Any] = [repo]
    if pr is not None:
        query += " AND pr_number = ?"
        params.append(pr)
    query += " ORDER BY created_at ASC"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    expected_prev = "0" * 64
    checked = 0
    for row in rows:
        checked += 1
        previous_hash = row["previous_hash"] or ""
        if previous_hash != expected_prev:
            return {
                "valid": False,
                "checked": checked,
                "reason": "previous_hash mismatch",
                "override_id": row["override_id"],
            }

        payload = {
            "repo": row["repo"],
            "pr_number": row["pr_number"],
            "issue_key": row["issue_key"],
            "decision_id": row["decision_id"],
            "actor": row["actor"],
            "reason": row["reason"],
            "previous_hash": previous_hash,
            "created_at": row["created_at"],
        }
        expected_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        if expected_hash != row["event_hash"]:
            return {
                "valid": False,
                "checked": checked,
                "reason": "event_hash mismatch",
                "override_id": row["override_id"],
            }

        expected_prev = row["event_hash"]

    return {"valid": True, "checked": checked}
