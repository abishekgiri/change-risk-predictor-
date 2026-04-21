"""ChangeRecord — the central lifecycle object for Phase 8.

A ChangeRecord is not an event log.  It is a single object that accumulates
system links as a change moves through the SDLC:

    Jira issue → PR → ReleaseGate decision → Deploy → (Incident → Hotfix)

At every transition the gate check validates:
  1. The state machine allows the transition
  2. All required links for the target state are present
  3. No missing-link rules are violated

ID format: chg_YYYYMMDD_uuid8  (consistent with rg_dec_ from Phase 7)
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.fabric.lifecycle import (
    check_required_links,
    evaluate_missing_links as _lifecycle_missing,
    validate_transition,
)
from releasegate.fabric.missing_links import evaluate_missing_links, should_block

logger = logging.getLogger(__name__)

_TABLE = "change_records"


# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------

def format_change_id(raw_id: str, created_at: str) -> str:
    """Return the human-readable chg_YYYYMMDD_uuid8 form."""
    date_part = created_at[:10].replace("-", "")
    uuid_part = raw_id.replace("-", "")[:8]
    return f"chg_{date_part}_{uuid_part}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _utc_now().isoformat()


# ---------------------------------------------------------------------------
# Schema bootstrap (called lazily)
# ---------------------------------------------------------------------------

def _ensure_table(storage: Any) -> None:
    """Create change_records table if it doesn't exist."""
    storage.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {_TABLE} (
            tenant_id           TEXT NOT NULL,
            change_id           TEXT NOT NULL,
            lifecycle_state     TEXT NOT NULL DEFAULT 'CREATED',
            enforcement_mode    TEXT NOT NULL DEFAULT 'STRICT',
            jira_issue_key      TEXT,
            pr_repo             TEXT,
            pr_number           INTEGER,
            pr_sha              TEXT,
            deploy_id           TEXT,
            rg_decision_ids     TEXT,
            incident_id         TEXT,
            hotfix_id           TEXT,
            environment         TEXT,
            actor               TEXT,
            missing_links       TEXT,
            violation_codes     TEXT,
            linked_at           TEXT,
            approved_at         TEXT,
            deployed_at         TEXT,
            incident_at         TEXT,
            closed_at           TEXT,
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            PRIMARY KEY (tenant_id, change_id)
        )
        """
    )
    for idx_sql in [
        f"CREATE INDEX IF NOT EXISTS idx_change_records_tenant_state ON {_TABLE}(tenant_id, lifecycle_state, updated_at DESC)",
        f"CREATE INDEX IF NOT EXISTS idx_change_records_tenant_jira  ON {_TABLE}(tenant_id, jira_issue_key)",
        f"CREATE INDEX IF NOT EXISTS idx_change_records_tenant_deploy ON {_TABLE}(tenant_id, deploy_id)",
        f"CREATE INDEX IF NOT EXISTS idx_change_records_tenant_incident ON {_TABLE}(tenant_id, incident_id)",
    ]:
        try:
            storage.execute(idx_sql)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _decode_json_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        return json.loads(value)
    except Exception:
        return [str(value)] if value else []


def _encode_json_list(values: List[str]) -> str:
    return json.dumps(values)


def _row_to_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "change_id":        row.get("change_id"),
        "tenant_id":        row.get("tenant_id"),
        "lifecycle_state":  row.get("lifecycle_state", "CREATED"),
        "enforcement_mode": row.get("enforcement_mode", "STRICT"),
        "jira_issue_key":   row.get("jira_issue_key"),
        "pr_repo":          row.get("pr_repo"),
        "pr_number":        row.get("pr_number"),
        "pr_sha":           row.get("pr_sha"),
        "deploy_id":        row.get("deploy_id"),
        "rg_decision_ids":  _decode_json_list(row.get("rg_decision_ids")),
        "incident_id":      row.get("incident_id"),
        "hotfix_id":        row.get("hotfix_id"),
        "environment":      row.get("environment"),
        "actor":            row.get("actor"),
        "missing_links":    _decode_json_list(row.get("missing_links")),
        "violation_codes":  _decode_json_list(row.get("violation_codes")),
        "linked_at":        row.get("linked_at"),
        "approved_at":      row.get("approved_at"),
        "deployed_at":      row.get("deployed_at"),
        "incident_at":      row.get("incident_at"),
        "closed_at":        row.get("closed_at"),
        "created_at":       row.get("created_at"),
        "updated_at":       row.get("updated_at"),
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def _fetch(storage: Any, tenant_id: str, change_id: str) -> Optional[Dict[str, Any]]:
    row = storage.fetchone(
        f"SELECT * FROM {_TABLE} WHERE tenant_id = ? AND change_id = ? LIMIT 1",
        (tenant_id, change_id),
    )
    return _row_to_dict(row) if row else None


def create_change(
    *,
    tenant_id: str,
    environment: str,
    actor: Optional[str] = None,
    jira_issue_key: Optional[str] = None,
    pr_repo: Optional[str] = None,
    pr_number: Optional[int] = None,
    pr_sha: Optional[str] = None,
    enforcement_mode: str = "STRICT",
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a new ChangeRecord.  Returns the record dict including change_id."""
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_table(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    raw_id = str(uuid.uuid4())
    now = _utc_iso()
    change_id = format_change_id(raw_id, now)

    initial_state = "CREATED"
    # If we already have enough to link, jump to LINKED
    if jira_issue_key or pr_repo:
        initial_state = "LINKED"

    record_for_check: Dict[str, Any] = {
        "jira_issue_key": jira_issue_key,
        "pr_repo": pr_repo,
        "pr_sha": pr_sha,
        "deploy_id": None,
        "rg_decision_ids": [],
        "incident_id": None,
        "hotfix_id": None,
    }
    violations = evaluate_missing_links(
        record=record_for_check,
        policy_overrides=policy_overrides,
    )
    violation_codes = [v["code"] for v in violations]
    if should_block(violations=violations, enforcement_mode=enforcement_mode):
        initial_state = "BLOCKED"

    linked_at = now if initial_state == "LINKED" else None

    storage.execute(
        f"""
        INSERT INTO {_TABLE} (
            tenant_id, change_id, lifecycle_state, enforcement_mode,
            jira_issue_key, pr_repo, pr_number, pr_sha,
            deploy_id, rg_decision_ids, incident_id, hotfix_id,
            environment, actor,
            missing_links, violation_codes,
            linked_at, approved_at, deployed_at, incident_at, closed_at,
            created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            effective_tenant, change_id, initial_state, enforcement_mode,
            jira_issue_key, pr_repo, pr_number, pr_sha,
            None, _encode_json_list([]), None, None,
            environment, actor,
            _encode_json_list([v["code"] for v in violations]),
            _encode_json_list(violation_codes),
            linked_at, None, None, None, None,
            now, now,
        ),
    )
    record = _fetch(storage, effective_tenant, change_id)
    if not record:
        raise RuntimeError("Failed to create change record")
    logger.info("Created ChangeRecord %s (state=%s)", change_id, initial_state)
    return record


def link_system(
    *,
    tenant_id: str,
    change_id: str,
    jira_issue_key: Optional[str] = None,
    pr_repo: Optional[str] = None,
    pr_number: Optional[int] = None,
    pr_sha: Optional[str] = None,
    deploy_id: Optional[str] = None,
    rg_decision_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    hotfix_id: Optional[str] = None,
    actor: Optional[str] = None,
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Add a system link to an existing ChangeRecord and advance lifecycle state."""
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_table(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    record = _fetch(storage, effective_tenant, change_id)
    if not record:
        raise ValueError(f"ChangeRecord not found: {change_id}")

    if record["lifecycle_state"] == "CLOSED":
        raise ValueError("Cannot link to a CLOSED change record.")

    # Merge new values (never overwrite non-null with null)
    def _merge(existing: Any, incoming: Any) -> Any:
        return incoming if incoming is not None else existing

    merged_jira    = _merge(record["jira_issue_key"], jira_issue_key)
    merged_pr_repo = _merge(record["pr_repo"], pr_repo)
    merged_pr_num  = _merge(record["pr_number"], pr_number)
    merged_pr_sha  = _merge(record["pr_sha"], pr_sha)
    merged_deploy  = _merge(record["deploy_id"], deploy_id)
    merged_incident = _merge(record["incident_id"], incident_id)
    merged_hotfix  = _merge(record["hotfix_id"], hotfix_id)
    merged_actor   = _merge(record["actor"], actor)

    # Merge decision IDs (append)
    existing_decisions: List[str] = list(record["rg_decision_ids"] or [])
    if rg_decision_id and rg_decision_id not in existing_decisions:
        existing_decisions.append(rg_decision_id)

    updated_record_snapshot: Dict[str, Any] = {
        "jira_issue_key": merged_jira,
        "pr_repo":        merged_pr_repo,
        "pr_sha":         merged_pr_sha,
        "deploy_id":      merged_deploy,
        "rg_decision_ids": existing_decisions,
        "incident_id":    merged_incident,
        "hotfix_id":      merged_hotfix,
    }

    # Re-evaluate missing links
    violations = evaluate_missing_links(
        record=updated_record_snapshot,
        policy_overrides=policy_overrides,
    )
    enforcement_mode = record["enforcement_mode"]
    blocked = should_block(violations=violations, enforcement_mode=enforcement_mode)

    # Advance state
    current_state = record["lifecycle_state"]
    now = _utc_iso()

    if blocked:
        new_state = "BLOCKED"
    else:
        # Determine natural next state from what was just added
        if current_state in ("CREATED", "BLOCKED") and (merged_jira or merged_pr_repo):
            new_state = "LINKED"
        elif current_state == "LINKED" and existing_decisions:
            new_state = "APPROVED"
        elif current_state == "APPROVED" and merged_deploy:
            new_state = "DEPLOYED"
        elif current_state == "DEPLOYED" and merged_incident:
            new_state = "INCIDENT_ACTIVE"
        elif current_state == "INCIDENT_ACTIVE" and merged_hotfix:
            new_state = "HOTFIX_IN_PROGRESS"
        else:
            new_state = current_state  # no change

    # Validate transition
    if new_state != current_state:
        err = validate_transition(current_state=current_state, target_state=new_state)
        if err:
            new_state = current_state  # keep current if transition illegal

    # Compute timestamps
    linked_at   = record["linked_at"]   or (now if new_state == "LINKED" else None)
    approved_at = record["approved_at"] or (now if new_state == "APPROVED" else None)
    deployed_at = record["deployed_at"] or (now if new_state == "DEPLOYED" else None)
    incident_at = record["incident_at"] or (now if new_state == "INCIDENT_ACTIVE" else None)

    storage.execute(
        f"""
        UPDATE {_TABLE}
        SET lifecycle_state = ?,
            jira_issue_key  = ?,
            pr_repo         = ?,
            pr_number       = ?,
            pr_sha          = ?,
            deploy_id       = ?,
            rg_decision_ids = ?,
            incident_id     = ?,
            hotfix_id       = ?,
            actor           = ?,
            missing_links   = ?,
            violation_codes = ?,
            linked_at       = ?,
            approved_at     = ?,
            deployed_at     = ?,
            incident_at     = ?,
            updated_at      = ?
        WHERE tenant_id = ? AND change_id = ?
        """,
        (
            new_state,
            merged_jira, merged_pr_repo, merged_pr_num, merged_pr_sha,
            merged_deploy,
            _encode_json_list(existing_decisions),
            merged_incident, merged_hotfix, merged_actor,
            _encode_json_list([v["code"] for v in violations]),
            _encode_json_list([v["code"] for v in violations]),
            linked_at, approved_at, deployed_at, incident_at,
            now,
            effective_tenant, change_id,
        ),
    )
    updated = _fetch(storage, effective_tenant, change_id)
    if not updated:
        raise RuntimeError("Failed to update change record")
    logger.info("Linked system to ChangeRecord %s (state=%s→%s)", change_id, current_state, new_state)
    return updated


def gate_check(
    *,
    tenant_id: str,
    change_id: str,
    target_state: Optional[str] = None,
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate whether the change is allowed to proceed.

    Returns:
        allowed (bool), current_state, violations, missing_links, message
    """
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_table(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    record = _fetch(storage, effective_tenant, change_id)
    if not record:
        return {
            "allowed": False,
            "current_state": None,
            "violations": [{"code": "CHANGE_NOT_FOUND", "message": f"ChangeRecord {change_id} not found."}],
            "missing_links": [],
            "message": f"BLOCKED: ChangeRecord {change_id} not found.",
        }

    violations = evaluate_missing_links(
        record={
            "jira_issue_key": record["jira_issue_key"],
            "pr_repo":        record["pr_repo"],
            "pr_sha":         record["pr_sha"],
            "deploy_id":      record["deploy_id"],
            "rg_decision_ids": _encode_json_list(record["rg_decision_ids"] or []),
            "incident_id":    record["incident_id"],
            "hotfix_id":      record["hotfix_id"],
        },
        policy_overrides=policy_overrides,
    )

    # Check state transition if target provided
    transition_error: Optional[str] = None
    if target_state:
        transition_error = validate_transition(
            current_state=record["lifecycle_state"],
            target_state=target_state,
        )
        # Check required links for target state
        missing_for_target = check_required_links(
            target_state=target_state,
            record={
                "jira_issue_key": record["jira_issue_key"],
                "pr_repo":        record["pr_repo"],
                "pr_sha":         record["pr_sha"],
                "deploy_id":      record["deploy_id"],
                "rg_decision_ids": _encode_json_list(record["rg_decision_ids"] or []),
                "incident_id":    record["incident_id"],
                "hotfix_id":      record["hotfix_id"],
            },
            is_hotfix=bool(record["hotfix_id"]),
        )
        for field in missing_for_target:
            violations.append({
                "code": f"MISSING_LINK_{field.upper()}",
                "rule": f"require_{field}",
                "message": f"Field '{field}' is required before entering state {target_state}.",
            })
        if transition_error:
            violations.append({
                "code": "ILLEGAL_TRANSITION",
                "rule": "lifecycle",
                "message": transition_error,
            })

    enforcement_mode = record["enforcement_mode"]
    blocked = should_block(violations=violations, enforcement_mode=enforcement_mode)
    allowed = not blocked

    if allowed:
        msg = f"ALLOWED: ChangeRecord {change_id} may proceed (state={record['lifecycle_state']})."
    else:
        codes = ", ".join(v["code"] for v in violations)
        msg = f"BLOCKED: ChangeRecord {change_id} has violations: {codes}."

    return {
        "allowed":       allowed,
        "current_state": record["lifecycle_state"],
        "enforcement_mode": enforcement_mode,
        "violations":    violations,
        "missing_links": [v["code"] for v in violations],
        "message":       msg,
        "record":        record,
    }


def close_change(
    *,
    tenant_id: str,
    change_id: str,
) -> Dict[str, Any]:
    """Transition a VERIFIED change to CLOSED."""
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_table(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    record = _fetch(storage, effective_tenant, change_id)
    if not record:
        raise ValueError(f"ChangeRecord not found: {change_id}")

    err = validate_transition(
        current_state=record["lifecycle_state"],
        target_state="CLOSED",
    )
    if err:
        raise ValueError(err)

    now = _utc_iso()
    storage.execute(
        f"UPDATE {_TABLE} SET lifecycle_state = 'CLOSED', closed_at = ?, updated_at = ? "
        f"WHERE tenant_id = ? AND change_id = ?",
        (now, now, effective_tenant, change_id),
    )
    return _fetch(storage, effective_tenant, change_id) or record


def get_change(*, tenant_id: str, change_id: str) -> Optional[Dict[str, Any]]:
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_table(storage)
    return _fetch(storage, resolve_tenant_id(tenant_id), change_id)


def list_changes(
    *,
    tenant_id: str,
    lifecycle_state: Optional[str] = None,
    environment: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_table(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    conditions = ["tenant_id = ?"]
    params: List[Any] = [effective_tenant]

    if lifecycle_state:
        conditions.append("lifecycle_state = ?")
        params.append(lifecycle_state)
    if environment:
        conditions.append("environment = ?")
        params.append(environment)

    params.append(min(limit, 500))
    where = " AND ".join(conditions)
    rows = storage.fetchall(
        f"SELECT * FROM {_TABLE} WHERE {where} ORDER BY updated_at DESC LIMIT ?",
        tuple(params),
    )
    return [_row_to_dict(r) for r in (rows or [])]


def trace_change(
    *,
    tenant_id: str,
    change_id: str,
) -> Dict[str, Any]:
    """Build a full end-to-end trace for a ChangeRecord.

    Pulls linked data from audit_decisions, deployment_decision_links, and
    cross_system_correlations to give auditors a single complete picture.
    """
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_table(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    record = _fetch(storage, effective_tenant, change_id)
    if not record:
        return {"ok": False, "error": f"ChangeRecord {change_id} not found."}

    decision_nodes: List[Dict[str, Any]] = []
    for rg_id in (record["rg_decision_ids"] or []):
        try:
            row = storage.fetchone(
                "SELECT decision_id, release_status, repo, created_at, policy_hash, replay_hash "
                "FROM audit_decisions WHERE tenant_id = ? AND decision_id LIKE ? LIMIT 1",
                (effective_tenant, f"{rg_id[:8]}%"),
            )
            if row:
                decision_nodes.append({
                    "rg_decision_id": rg_id,
                    "decision_id":    row.get("decision_id"),
                    "status":         row.get("release_status"),
                    "repo":           row.get("repo"),
                    "created_at":     row.get("created_at"),
                    "policy_hash":    row.get("policy_hash"),
                    "replay_hash":    row.get("replay_hash"),
                })
        except Exception as exc:
            logger.debug("Could not fetch decision node %s: %s", rg_id, exc)

    deploy_node: Optional[Dict[str, Any]] = None
    if record["deploy_id"]:
        try:
            row = storage.fetchone(
                "SELECT * FROM deployment_decision_links WHERE tenant_id = ? AND deployment_event_id = ? LIMIT 1",
                (effective_tenant, record["deploy_id"]),
            )
            if row:
                deploy_node = {
                    "deploy_id":        row.get("deployment_event_id"),
                    "environment":      row.get("environment"),
                    "deployed_at":      row.get("deployed_at"),
                    "contract_verdict": row.get("contract_verdict"),
                    "violation_codes":  json.loads(row.get("violation_codes_json") or "[]"),
                }
        except Exception as exc:
            logger.debug("Could not fetch deploy node: %s", exc)

    correlation_node: Optional[Dict[str, Any]] = None
    try:
        row = storage.fetchone(
            "SELECT * FROM cross_system_correlations WHERE tenant_id = ? AND (deploy_id = ? OR jira_issue_key = ?) LIMIT 1",
            (effective_tenant, record["deploy_id"], record["jira_issue_key"]),
        )
        if row:
            correlation_node = {
                "correlation_id": row.get("correlation_id"),
                "jira_issue_key": row.get("jira_issue_key"),
                "pr_repo":        row.get("pr_repo"),
                "deploy_id":      row.get("deploy_id"),
                "incident_id":    row.get("incident_id"),
                "environment":    row.get("environment"),
            }
    except Exception as exc:
        logger.debug("Could not fetch correlation node: %s", exc)

    return {
        "ok":          True,
        "change_id":   change_id,
        "record":      record,
        "decisions":   decision_nodes,
        "deployment":  deploy_node,
        "correlation": correlation_node,
        "completeness": {
            "has_jira":     bool(record["jira_issue_key"]),
            "has_pr":       bool(record["pr_repo"]),
            "has_decision": bool(record["rg_decision_ids"]),
            "has_deploy":   bool(record["deploy_id"]),
            "has_incident_traced": (
                bool(record["incident_id"]) and bool(record["deploy_id"])
            ),
            "lifecycle_closed": record["lifecycle_state"] == "CLOSED",
        },
    }


def fabric_health(
    *,
    tenant_id: str,
    days: int = 30,
) -> Dict[str, Any]:
    """Cross-system correlation health summary for the dashboard."""
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    from datetime import timedelta
    init_db()
    storage = get_storage_backend()
    _ensure_table(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    def _count(condition: str, params: tuple) -> int:
        row = storage.fetchone(
            f"SELECT COUNT(*) as cnt FROM {_TABLE} WHERE tenant_id = ? AND created_at >= ? AND {condition}",
            (effective_tenant, cutoff) + params,
        )
        return int((row.get("cnt") or 0) if row else 0)

    total_row = storage.fetchone(
        f"SELECT COUNT(*) as cnt FROM {_TABLE} WHERE tenant_id = ? AND created_at >= ?",
        (effective_tenant, cutoff),
    )
    total = int((total_row.get("cnt") or 0) if total_row else 0)

    by_state_rows = storage.fetchall(
        f"SELECT lifecycle_state, COUNT(*) as cnt FROM {_TABLE} "
        f"WHERE tenant_id = ? AND created_at >= ? GROUP BY lifecycle_state",
        (effective_tenant, cutoff),
    ) or []
    by_state = {r.get("lifecycle_state"): int(r.get("cnt") or 0) for r in by_state_rows}

    blocked   = by_state.get("BLOCKED", 0)
    deployed  = by_state.get("DEPLOYED", 0) + by_state.get("VERIFIED", 0) + by_state.get("CLOSED", 0)
    incidents = _count("incident_id IS NOT NULL", ())
    orphan_deploys = _count("deploy_id IS NOT NULL AND (jira_issue_key IS NULL OR pr_repo IS NULL)", ())

    coverage_pct = round(deployed / total * 100, 1) if total > 0 else 0.0
    block_rate   = round(blocked  / total * 100, 1) if total > 0 else 0.0

    return {
        "ok":             True,
        "tenant_id":      effective_tenant,
        "window_days":    days,
        "total_changes":  total,
        "by_state":       by_state,
        "deployed_count": deployed,
        "blocked_count":  blocked,
        "incident_count": incidents,
        "orphan_deploys": orphan_deploys,
        "coverage_pct":   coverage_pct,
        "block_rate_pct": block_rate,
        "health_verdict": (
            "HEALTHY"   if orphan_deploys == 0 and block_rate < 5 else
            "DEGRADED"  if orphan_deploys <= 2 or block_rate < 20 else
            "CRITICAL"
        ),
    }
