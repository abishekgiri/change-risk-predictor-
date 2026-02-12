from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _get_last_hash(repo: str, tenant_id: str) -> Optional[str]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT event_hash
        FROM audit_overrides
        WHERE tenant_id = ? AND repo = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (tenant_id, repo),
    )
    return row.get("event_hash") if row else None


def record_override(
    repo: str,
    pr_number: Optional[int] = None,
    issue_key: Optional[str] = None,
    decision_id: Optional[str] = None,
    actor: Optional[str] = None,
    reason: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Append-only tenant-scoped override ledger record with hash chaining.
    """
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    effective_target_type = target_type or "pr"
    effective_target_id = target_id or (f"{repo}#{pr_number}" if pr_number is not None else repo)
    now = datetime.now(timezone.utc).isoformat()
    max_attempts = 3
    for _attempt in range(max_attempts):
        prev_hash = _get_last_hash(repo=repo, tenant_id=effective_tenant) or ("0" * 64)
        payload = {
            "tenant_id": effective_tenant,
            "repo": repo,
            "pr_number": pr_number,
            "issue_key": issue_key,
            "decision_id": decision_id,
            "actor": actor,
            "reason": reason,
            "target_type": effective_target_type,
            "target_id": effective_target_id,
            "previous_hash": prev_hash,
            "created_at": now,
        }
        if idempotency_key is not None:
            payload["idempotency_key"] = idempotency_key
        event_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        override_id = hashlib.sha256(f"{effective_tenant}:{repo}:{now}:{event_hash}".encode()).hexdigest()[:32]

        try:
            storage.execute(
                """
                INSERT INTO audit_overrides (
                    override_id, tenant_id, decision_id, repo, pr_number, issue_key, actor, reason, target_type, target_id, idempotency_key, previous_hash, event_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    override_id,
                    effective_tenant,
                    decision_id,
                    repo,
                    pr_number,
                    issue_key,
                    actor,
                    reason,
                    effective_target_type,
                    effective_target_id,
                    idempotency_key,
                    prev_hash,
                    event_hash,
                    now,
                ),
            )
            payload["override_id"] = override_id
            payload["event_hash"] = event_hash
            return payload
        except Exception as exc:
            lowered = str(exc).lower()
            if idempotency_key and ("idempotency" in lowered or "unique" in lowered):
                existing = storage.fetchone(
                    """
                    SELECT * FROM audit_overrides
                    WHERE tenant_id = ? AND idempotency_key = ?
                    LIMIT 1
                    """,
                    (effective_tenant, idempotency_key),
                )
                if existing:
                    return existing
            # Parallel append race: another writer advanced the chain tip first.
            if "previous_hash" in lowered and "unique" in lowered:
                continue
            raise
    raise RuntimeError("Unable to append override after retries due to concurrent ledger updates")


def list_overrides(
    repo: str,
    limit: int = 200,
    pr: Optional[int] = None,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    query = "SELECT * FROM audit_overrides WHERE tenant_id = ? AND repo = ?"
    params: List[Any] = [effective_tenant, repo]
    if pr is not None:
        query += " AND pr_number = ?"
        params.append(pr)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    return storage.fetchall(query, params)


def get_active_override(
    *,
    tenant_id: Optional[str],
    target_type: str,
    target_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    return storage.fetchone(
        """
        SELECT *
        FROM audit_overrides
        WHERE tenant_id = ? AND target_type = ? AND target_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (effective_tenant, target_type, target_id),
    )


def verify_override_chain(repo: str, pr: Optional[int] = None, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify tenant-scoped override hash-chain integrity.
    """
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)

    query = """
        SELECT override_id, tenant_id, decision_id, repo, pr_number, issue_key, actor, reason, target_type, target_id, idempotency_key, previous_hash, event_hash, created_at
        FROM audit_overrides
        WHERE tenant_id = ? AND repo = ?
    """
    params: List[Any] = [effective_tenant, repo]
    if pr is not None:
        query += " AND pr_number = ?"
        params.append(pr)
    query += " ORDER BY created_at ASC"
    rows = storage.fetchall(query, params)

    expected_prev = "0" * 64
    checked = 0
    for row in rows:
        checked += 1
        previous_hash = row.get("previous_hash") or ""
        if previous_hash != expected_prev:
            return {
                "valid": False,
                "checked": checked,
                "reason": "previous_hash mismatch",
                "override_id": row.get("override_id"),
                "tenant_id": effective_tenant,
            }

        payload = {
            "tenant_id": row.get("tenant_id"),
            "repo": row.get("repo"),
            "pr_number": row.get("pr_number"),
            "issue_key": row.get("issue_key"),
            "decision_id": row.get("decision_id"),
            "actor": row.get("actor"),
            "reason": row.get("reason"),
            "target_type": row.get("target_type"),
            "target_id": row.get("target_id"),
            "previous_hash": previous_hash,
            "created_at": row.get("created_at"),
        }
        if row.get("idempotency_key") is not None:
            payload["idempotency_key"] = row.get("idempotency_key")
        expected_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        if expected_hash != row.get("event_hash"):
            return {
                "valid": False,
                "checked": checked,
                "reason": "event_hash mismatch",
                "override_id": row.get("override_id"),
                "tenant_id": effective_tenant,
            }

        expected_prev = row.get("event_hash") or ""

    return {"valid": True, "checked": checked, "tenant_id": effective_tenant}


def verify_all_override_chains(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify all override chains, grouped by tenant + repo.
    """
    init_db()
    storage = get_storage_backend()
    if tenant_id:
        effective_tenant = resolve_tenant_id(tenant_id)
        rows = storage.fetchall(
            "SELECT DISTINCT tenant_id, repo FROM audit_overrides WHERE tenant_id = ? ORDER BY repo ASC",
            (effective_tenant,),
        )
    else:
        rows = storage.fetchall("SELECT DISTINCT tenant_id, repo FROM audit_overrides ORDER BY tenant_id ASC, repo ASC")

    results = []
    all_valid = True
    for row in rows:
        tenant = row.get("tenant_id")
        repo = row.get("repo")
        res = verify_override_chain(repo=repo, tenant_id=tenant)
        result = {"tenant_id": tenant, "repo": repo, **res}
        results.append(result)
        if not res.get("valid", False):
            all_valid = False

    return {
        "valid": all_valid,
        "checked_chains": len(rows),
        "results": results,
    }
