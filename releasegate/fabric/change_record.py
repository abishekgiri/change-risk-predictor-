"""ChangeRecord — the central lifecycle object for Phase 8.

Architecture
------------
ChangeRecord is a **materialized view** over two source-of-truth tables:

    cross_system_correlations  →  what systems are linked (Jira, PR, deploy, incident)
    audit_decisions            →  what governance decisions were made

The ``change_records`` table owns ONLY:
  - change_id (chg_YYYYMMDD_uuid8)
  - lifecycle_state (the state machine)
  - enforcement_mode (STRICT / AUDIT)
  - correlation_id (FK → cross_system_correlations)
  - timestamps (created_at, linked_at, approved_at, deployed_at, ...)
  - violation_codes (last evaluated missing-link violations)

Link data (jira_issue_key, pr_repo, deploy_id, rg_decision_ids, ...) is
ALWAYS read from cross_system_correlations + audit_decisions — never duplicated
into change_records.  This prevents the two tables from drifting semantically.

Every state transition is recorded in ``change_state_transitions`` for full
audit history.

Correlation fingerprint
-----------------------
We use a flexible fingerprint rather than a strict SHA-256 of
(jira, repo, commit, env):

    fingerprint = SHA-256 of canonical JSON({
        jira_id, repo, branch or merge_commit,
        commit_range or commit_sha,  ← whichever is available
        environment
    })

This handles hotfixes (no PR), squash merges, cherry-picks and
multi-commit deploys without forcing the caller to provide a precise SHA.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from releasegate.fabric.lifecycle import (
    check_required_links,
    validate_transition,
)
from releasegate.fabric.missing_links import evaluate_missing_links, should_block

logger = logging.getLogger(__name__)

_TABLE       = "change_records"
_TRANSITIONS = "change_state_transitions"


# ---------------------------------------------------------------------------
# ID + fingerprint helpers
# ---------------------------------------------------------------------------

def format_change_id(raw_id: str, created_at: str) -> str:
    date_part = created_at[:10].replace("-", "")
    uuid_part = raw_id.replace("-", "")[:8]
    return f"chg_{date_part}_{uuid_part}"


def compute_change_fingerprint(
    *,
    jira_id: Optional[str] = None,
    repo: Optional[str] = None,
    branch: Optional[str] = None,
    commit_sha: Optional[str] = None,
    commit_range: Optional[str] = None,
    environment: Optional[str] = None,
) -> str:
    """Flexible change fingerprint.

    Prefers commit_range over commit_sha to support multi-commit deploys.
    Falls back gracefully when PR details are absent (hotfix, cherry-pick).
    """
    payload: Dict[str, str] = {
        "jira_id":     (jira_id or "").strip().lower(),
        "repo":        (repo or "").strip().lower(),
        "branch":      (branch or "").strip().lower(),
        "commit":      (commit_range or commit_sha or "").strip().lower(),
        "environment": (environment or "").strip().lower(),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "fp_" + hashlib.sha256(canonical.encode()).hexdigest()[:24]


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

def _ensure_tables(storage: Any) -> None:
    storage.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {_TABLE} (
            tenant_id        TEXT NOT NULL,
            change_id        TEXT NOT NULL,
            lifecycle_state  TEXT NOT NULL DEFAULT 'CREATED',
            enforcement_mode TEXT NOT NULL DEFAULT 'STRICT',
            correlation_id   TEXT,
            violation_codes  TEXT,
            linked_at        TEXT,
            approved_at      TEXT,
            deployed_at      TEXT,
            incident_at      TEXT,
            closed_at        TEXT,
            created_at       TEXT NOT NULL,
            updated_at       TEXT NOT NULL,
            PRIMARY KEY (tenant_id, change_id)
        )
        """
    )
    storage.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {_TRANSITIONS} (
            tenant_id      TEXT NOT NULL,
            change_id      TEXT NOT NULL,
            from_state     TEXT NOT NULL,
            to_state       TEXT NOT NULL,
            event          TEXT,
            actor          TEXT,
            violation_codes TEXT,
            created_at     TEXT NOT NULL
        )
        """
    )
    for idx in [
        f"CREATE INDEX IF NOT EXISTS idx_cr_tenant_state  ON {_TABLE}({_TABLE}.tenant_id, lifecycle_state, updated_at DESC)",
        f"CREATE INDEX IF NOT EXISTS idx_cr_tenant_corr   ON {_TABLE}({_TABLE}.tenant_id, correlation_id)",
        f"CREATE INDEX IF NOT EXISTS idx_cst_change       ON {_TRANSITIONS}(tenant_id, change_id, created_at DESC)",
    ]:
        try:
            storage.execute(idx)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _decode_json_list(v: Any) -> List[str]:
    if not v:
        return []
    if isinstance(v, list):
        return v
    try:
        return json.loads(v)
    except Exception:
        return [str(v)] if v else []


def _encode_json_list(vs: List[str]) -> str:
    return json.dumps(vs)


def _fetch_record(storage: Any, tenant_id: str, change_id: str) -> Optional[Dict[str, Any]]:
    return storage.fetchone(
        f"SELECT * FROM {_TABLE} WHERE tenant_id = ? AND change_id = ? LIMIT 1",
        (tenant_id, change_id),
    )


def _get_correlation(storage: Any, tenant_id: str, correlation_id: str) -> Optional[Dict[str, Any]]:
    if not correlation_id:
        return None
    return storage.fetchone(
        """SELECT * FROM cross_system_correlations
           WHERE tenant_id = ? AND correlation_id = ? LIMIT 1""",
        (tenant_id, correlation_id),
    )


def _get_decision_ids(storage: Any, tenant_id: str, correlation_id: Optional[str]) -> List[str]:
    """Fetch rg_dec_… IDs for decisions linked via this correlation."""
    if not correlation_id:
        return []
    rows = storage.fetchall(
        """SELECT decision_id, created_at FROM audit_decisions
           WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 20""",
        (tenant_id,),
    ) or []
    # Correlate by presence in deployment_decision_links if possible
    try:
        linked = storage.fetchall(
            """SELECT decision_id FROM deployment_decision_links
               WHERE tenant_id = ? ORDER BY deployed_at DESC LIMIT 20""",
            (tenant_id,),
        ) or []
        linked_ids = {r.get("decision_id") for r in linked}
        return [r.get("decision_id") for r in rows if r.get("decision_id") in linked_ids][:10]
    except Exception:
        return []


def _materialize(
    record_row: Dict[str, Any],
    corr: Optional[Dict[str, Any]],
    decision_ids: List[str],
) -> Dict[str, Any]:
    """Materialize a ChangeRecord by merging the state-machine row with
    live link data from cross_system_correlations + audit_decisions.
    """
    from releasegate.decisions.registry import format_rg_decision_id
    rg_ids = []
    for did in decision_ids:
        try:
            rg_ids.append(format_rg_decision_id(did, _utc_iso()))
        except Exception:
            rg_ids.append(did)

    return {
        # State-machine owned fields
        "change_id":        record_row.get("change_id"),
        "tenant_id":        record_row.get("tenant_id"),
        "lifecycle_state":  record_row.get("lifecycle_state", "CREATED"),
        "enforcement_mode": record_row.get("enforcement_mode", "STRICT"),
        "correlation_id":   record_row.get("correlation_id"),
        "violation_codes":  _decode_json_list(record_row.get("violation_codes")),
        "linked_at":        record_row.get("linked_at"),
        "approved_at":      record_row.get("approved_at"),
        "deployed_at":      record_row.get("deployed_at"),
        "incident_at":      record_row.get("incident_at"),
        "closed_at":        record_row.get("closed_at"),
        "created_at":       record_row.get("created_at"),
        "updated_at":       record_row.get("updated_at"),
        # Materialized from cross_system_correlations (source of truth)
        "jira_issue_key":  corr.get("jira_issue_key") if corr else None,
        "pr_repo":         corr.get("pr_repo")        if corr else None,
        "pr_sha":          corr.get("pr_sha")         if corr else None,
        "deploy_id":       corr.get("deploy_id")      if corr else None,
        "incident_id":     corr.get("incident_id")    if corr else None,
        "environment":     corr.get("environment")    if corr else None,
        "change_ticket":   corr.get("change_ticket_key") if corr else None,
        # Materialized from audit_decisions
        "rg_decision_ids": rg_ids,
    }


def _record_transition(
    storage: Any,
    tenant_id: str,
    change_id: str,
    from_state: str,
    to_state: str,
    *,
    event: Optional[str] = None,
    actor: Optional[str] = None,
    violation_codes: Optional[List[str]] = None,
) -> None:
    storage.execute(
        f"""INSERT INTO {_TRANSITIONS}
            (tenant_id, change_id, from_state, to_state, event, actor, violation_codes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            tenant_id, change_id, from_state, to_state,
            event, actor,
            _encode_json_list(violation_codes or []),
            _utc_iso(),
        ),
    )


def _fetch_full(
    storage: Any, tenant_id: str, change_id: str
) -> Optional[Dict[str, Any]]:
    row = _fetch_record(storage, tenant_id, change_id)
    if not row:
        return None
    corr_id = row.get("correlation_id")
    corr     = _get_correlation(storage, tenant_id, corr_id) if corr_id else None
    d_ids    = _get_decision_ids(storage, tenant_id, corr_id)
    return _materialize(row, corr, d_ids)


# ---------------------------------------------------------------------------
# Public CRUD
# ---------------------------------------------------------------------------

def create_change(
    *,
    tenant_id: str,
    environment: str,
    actor: Optional[str] = None,
    jira_issue_key: Optional[str] = None,
    pr_repo: Optional[str] = None,
    pr_number: Optional[int] = None,
    pr_sha: Optional[str] = None,
    branch: Optional[str] = None,
    commit_range: Optional[str] = None,
    enforcement_mode: str = "STRICT",
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    from releasegate.governance.correlation import create_correlation_record
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    now = _utc_iso()
    raw_id   = str(uuid.uuid4())
    change_id = format_change_id(raw_id, now)

    # Create the correlation record (source of truth for links)
    corr = create_correlation_record(
        tenant_id=effective_tenant,
        correlation_id=None,
        payload={
            "jira_issue_key": jira_issue_key,
            "pr_repo":        pr_repo,
            "pr_sha":         pr_sha,
            "environment":    environment,
        },
    )
    correlation_id = corr["correlation_id"]

    # Evaluate initial missing-link violations
    violations = evaluate_missing_links(
        record={"jira_issue_key": jira_issue_key, "pr_repo": pr_repo,
                "pr_sha": pr_sha, "deploy_id": None, "rg_decision_ids": [],
                "incident_id": None, "hotfix_id": None},
        policy_overrides=policy_overrides,
    )
    blocked = should_block(violations=violations, enforcement_mode=enforcement_mode)
    initial_state = "BLOCKED" if blocked else ("LINKED" if (jira_issue_key or pr_repo) else "CREATED")
    linked_at = now if initial_state == "LINKED" else None

    storage.execute(
        f"""INSERT INTO {_TABLE}
            (tenant_id, change_id, lifecycle_state, enforcement_mode,
             correlation_id, violation_codes,
             linked_at, approved_at, deployed_at, incident_at, closed_at,
             created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            effective_tenant, change_id, initial_state, enforcement_mode,
            correlation_id,
            _encode_json_list([v["code"] for v in violations]),
            linked_at, None, None, None, None,
            now, now,
        ),
    )
    _record_transition(
        storage, effective_tenant, change_id,
        from_state="—", to_state=initial_state,
        event="created", actor=actor,
        violation_codes=[v["code"] for v in violations],
    )
    return _fetch_full(storage, effective_tenant, change_id) or {}


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
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    from releasegate.governance.correlation import update_correlation_record
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    row = _fetch_record(storage, effective_tenant, change_id)
    if not row:
        raise ValueError(f"ChangeRecord not found: {change_id}")
    if row.get("lifecycle_state") == "CLOSED":
        raise ValueError("Cannot link to a CLOSED change record.")

    correlation_id = row.get("correlation_id")

    # Write links to cross_system_correlations (source of truth)
    try:
        update_correlation_record(
            tenant_id=effective_tenant,
            correlation_id=correlation_id,
            payload={k: v for k, v in {
                "jira_issue_key": jira_issue_key,
                "pr_repo":        pr_repo,
                "pr_sha":         pr_sha,
                "deploy_id":      deploy_id,
                "incident_id":    incident_id,
            }.items() if v is not None},
        )
    except ValueError:
        pass  # conflict on existing values — read back what's there

    # Materialize fresh state from source tables
    corr   = _get_correlation(storage, effective_tenant, correlation_id)
    d_ids  = _get_decision_ids(storage, effective_tenant, correlation_id)
    record = _materialize(row, corr, d_ids)

    # Re-evaluate violations against current (post-update) link state
    violations = evaluate_missing_links(
        record={
            "jira_issue_key": record.get("jira_issue_key"),
            "pr_repo":        record.get("pr_repo"),
            "pr_sha":         record.get("pr_sha"),
            "deploy_id":      record.get("deploy_id"),
            "rg_decision_ids": record.get("rg_decision_ids") or [],
            "incident_id":    record.get("incident_id"),
            "hotfix_id":      hotfix_id,
        },
        policy_overrides=policy_overrides,
    )
    enforcement_mode = row.get("enforcement_mode", "STRICT")
    blocked = should_block(violations=violations, enforcement_mode=enforcement_mode)

    current_state = row.get("lifecycle_state", "CREATED")
    now = _utc_iso()

    if blocked:
        new_state = "BLOCKED"
    else:
        jira  = record.get("jira_issue_key")
        pr    = record.get("pr_repo")
        dep   = record.get("deploy_id")
        inc   = record.get("incident_id")
        decs  = record.get("rg_decision_ids") or []

        if current_state in ("CREATED", "BLOCKED") and (jira or pr):
            new_state = "LINKED"
        elif current_state in ("LINKED", "CREATED") and decs:
            new_state = "APPROVED"
        elif current_state == "APPROVED" and dep:
            new_state = "DEPLOYED"
        elif current_state == "DEPLOYED" and inc:
            new_state = "INCIDENT_ACTIVE"
        elif current_state == "INCIDENT_ACTIVE" and hotfix_id:
            new_state = "HOTFIX_IN_PROGRESS"
        else:
            new_state = current_state

    if new_state != current_state:
        err = validate_transition(current_state=current_state, target_state=new_state)
        if err:
            new_state = current_state

    linked_at   = row.get("linked_at")   or (now if new_state == "LINKED" else None)
    approved_at = row.get("approved_at") or (now if new_state == "APPROVED" else None)
    deployed_at = row.get("deployed_at") or (now if new_state == "DEPLOYED" else None)
    incident_at = row.get("incident_at") or (now if new_state == "INCIDENT_ACTIVE" else None)

    storage.execute(
        f"""UPDATE {_TABLE} SET
            lifecycle_state = ?,
            violation_codes = ?,
            linked_at   = ?, approved_at = ?,
            deployed_at = ?, incident_at = ?,
            updated_at  = ?
            WHERE tenant_id = ? AND change_id = ?""",
        (
            new_state,
            _encode_json_list([v["code"] for v in violations]),
            linked_at, approved_at, deployed_at, incident_at,
            now,
            effective_tenant, change_id,
        ),
    )
    if new_state != current_state:
        _record_transition(
            storage, effective_tenant, change_id,
            from_state=current_state, to_state=new_state,
            event="link", actor=actor,
            violation_codes=[v["code"] for v in violations],
        )

    return _fetch_full(storage, effective_tenant, change_id) or {}


def gate_check(
    *,
    tenant_id: str,
    change_id: str,
    target_state: Optional[str] = None,
    policy_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    record = _fetch_full(storage, effective_tenant, change_id)
    if not record:
        return {
            "allowed": False, "current_state": None,
            "violations": [{"code": "CHANGE_NOT_FOUND",
                            "message": f"ChangeRecord {change_id} not found."}],
            "missing_links": [], "message": f"BLOCKED: {change_id} not found.",
        }

    violations = evaluate_missing_links(
        record={
            "jira_issue_key": record.get("jira_issue_key"),
            "pr_repo":        record.get("pr_repo"),
            "pr_sha":         record.get("pr_sha"),
            "deploy_id":      record.get("deploy_id"),
            "rg_decision_ids": _encode_json_list(record.get("rg_decision_ids") or []),
            "incident_id":    record.get("incident_id"),
            "hotfix_id":      None,
        },
        policy_overrides=policy_overrides,
    )

    if target_state:
        err = validate_transition(
            current_state=record["lifecycle_state"], target_state=target_state
        )
        missing_fields = check_required_links(
            target_state=target_state,
            record={
                "jira_issue_key": record.get("jira_issue_key"),
                "pr_repo":        record.get("pr_repo"),
                "pr_sha":         record.get("pr_sha"),
                "deploy_id":      record.get("deploy_id"),
                "rg_decision_ids": _encode_json_list(record.get("rg_decision_ids") or []),
                "incident_id":    record.get("incident_id"),
            },
        )
        for field in missing_fields:
            violations.append({
                "code": f"MISSING_{field.upper()}",
                "rule": f"require_{field}",
                "message": f"'{field}' required before {target_state}.",
            })
        if err:
            violations.append({"code": "ILLEGAL_TRANSITION", "rule": "lifecycle", "message": err})

    blocked = should_block(violations=violations, enforcement_mode=record["enforcement_mode"])
    codes   = [v["code"] for v in violations]
    msg = (
        f"ALLOWED: {change_id} may proceed (state={record['lifecycle_state']})."
        if not blocked else
        f"BLOCKED: {change_id} — {', '.join(codes)}."
    )
    return {
        "allowed": not blocked, "current_state": record["lifecycle_state"],
        "enforcement_mode": record["enforcement_mode"],
        "violations": violations, "missing_links": codes,
        "message": msg, "record": record,
    }


def close_change(*, tenant_id: str, change_id: str, actor: Optional[str] = None) -> Dict[str, Any]:
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    row = _fetch_record(storage, effective_tenant, change_id)
    if not row:
        raise ValueError(f"ChangeRecord not found: {change_id}")
    err = validate_transition(current_state=row.get("lifecycle_state", ""), target_state="CLOSED")
    if err:
        raise ValueError(err)
    now = _utc_iso()
    storage.execute(
        f"UPDATE {_TABLE} SET lifecycle_state='CLOSED', closed_at=?, updated_at=? WHERE tenant_id=? AND change_id=?",
        (now, now, effective_tenant, change_id),
    )
    _record_transition(storage, effective_tenant, change_id,
                       from_state=row["lifecycle_state"], to_state="CLOSED",
                       event="closed", actor=actor)
    return _fetch_full(storage, effective_tenant, change_id) or {}


def get_change(*, tenant_id: str, change_id: str) -> Optional[Dict[str, Any]]:
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)
    return _fetch_full(storage, resolve_tenant_id(tenant_id), change_id)


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
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    conditions = ["r.tenant_id = ?"]
    params: List[Any] = [effective_tenant]
    if lifecycle_state:
        conditions.append("r.lifecycle_state = ?")
        params.append(lifecycle_state)
    if environment:
        conditions.append("c.environment = ?")
        params.append(environment)
    params.append(min(limit, 500))

    where = " AND ".join(conditions)
    rows = storage.fetchall(
        f"""SELECT r.*, c.jira_issue_key, c.pr_repo, c.pr_sha,
                   c.deploy_id, c.incident_id, c.environment, c.change_ticket_key
            FROM {_TABLE} r
            LEFT JOIN cross_system_correlations c
              ON c.tenant_id = r.tenant_id AND c.correlation_id = r.correlation_id
            WHERE {where}
            ORDER BY r.updated_at DESC LIMIT ?""",
        tuple(params),
    ) or []
    result = []
    for row in rows:
        d_ids = _get_decision_ids(storage, effective_tenant, row.get("correlation_id"))
        result.append(_materialize(row, row, d_ids))
    return result


def get_state_history(*, tenant_id: str, change_id: str) -> List[Dict[str, Any]]:
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    rows = storage.fetchall(
        f"SELECT * FROM {_TRANSITIONS} WHERE tenant_id=? AND change_id=? ORDER BY created_at ASC",
        (effective_tenant, change_id),
    ) or []
    return [
        {
            "from_state":      r.get("from_state"),
            "to_state":        r.get("to_state"),
            "event":           r.get("event"),
            "actor":           r.get("actor"),
            "violation_codes": _decode_json_list(r.get("violation_codes")),
            "created_at":      r.get("created_at"),
        }
        for r in rows
    ]


def query_changes(
    *,
    tenant_id: str,
    filter_type: str,
    days: int = 30,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Governance query layer — answer named questions about the change landscape.

    filter_type values:
      orphan_deploys      — deploy_id set but pr_repo or jira_issue_key missing
      missing_jira        — pr_repo set but jira_issue_key missing
      missing_decision    — deploy_id set but no linked RG decision
      blocked             — lifecycle_state = BLOCKED
      incidents           — incident_id is not null
      open                — not CLOSED and not BLOCKED, older than 7 days
    """
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    from datetime import timedelta
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    FILTERS: Dict[str, str] = {
        "orphan_deploys":   "c.deploy_id IS NOT NULL AND (c.jira_issue_key IS NULL OR c.pr_repo IS NULL)",
        "missing_jira":     "c.pr_repo IS NOT NULL AND c.jira_issue_key IS NULL",
        "missing_decision": "c.deploy_id IS NOT NULL",
        "blocked":          "r.lifecycle_state = 'BLOCKED'",
        "incidents":        "c.incident_id IS NOT NULL",
        "open":             "r.lifecycle_state NOT IN ('CLOSED','BLOCKED')",
    }
    condition = FILTERS.get(filter_type)
    if not condition:
        return []

    rows = storage.fetchall(
        f"""SELECT r.*, c.jira_issue_key, c.pr_repo, c.pr_sha,
                   c.deploy_id, c.incident_id, c.environment, c.change_ticket_key
            FROM {_TABLE} r
            LEFT JOIN cross_system_correlations c
              ON c.tenant_id = r.tenant_id AND c.correlation_id = r.correlation_id
            WHERE r.tenant_id = ? AND r.created_at >= ? AND {condition}
            ORDER BY r.updated_at DESC LIMIT ?""",
        (effective_tenant, cutoff, min(limit, 500)),
    ) or []

    result = []
    for row in rows:
        d_ids = _get_decision_ids(storage, effective_tenant, row.get("correlation_id"))
        mat = _materialize(row, row, d_ids)
        # For missing_decision filter: only include if actually no decisions
        if filter_type == "missing_decision" and mat.get("rg_decision_ids"):
            continue
        result.append(mat)
    return result


def trace_change(*, tenant_id: str, change_id: str) -> Dict[str, Any]:
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    record = _fetch_full(storage, effective_tenant, change_id)
    if not record:
        return {"ok": False, "error": f"ChangeRecord {change_id} not found."}

    decision_nodes: List[Dict[str, Any]] = []
    for rg_id in (record.get("rg_decision_ids") or []):
        try:
            row = storage.fetchone(
                "SELECT decision_id, release_status, repo, created_at, policy_hash, replay_hash "
                "FROM audit_decisions WHERE tenant_id=? AND decision_id LIKE ? LIMIT 1",
                (effective_tenant, f"{rg_id[:8]}%"),
            )
            if row:
                decision_nodes.append({
                    "rg_decision_id": rg_id,
                    "decision_id":    row.get("decision_id"),
                    "status":         row.get("release_status"),
                    "repo":           row.get("repo"),
                    "created_at":     row.get("created_at"),
                    "replay_hash":    row.get("replay_hash"),
                })
        except Exception:
            pass

    deploy_node = None
    if record.get("deploy_id"):
        try:
            row = storage.fetchone(
                "SELECT * FROM deployment_decision_links WHERE tenant_id=? AND deployment_event_id=? LIMIT 1",
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
        except Exception:
            pass

    correlation_node = None
    corr_id = record.get("correlation_id")
    if corr_id:
        row = _get_correlation(storage, effective_tenant, corr_id)
        if row:
            correlation_node = {
                "correlation_id": row.get("correlation_id"),
                "jira_issue_key": row.get("jira_issue_key"),
                "pr_repo":        row.get("pr_repo"),
                "deploy_id":      row.get("deploy_id"),
                "incident_id":    row.get("incident_id"),
                "environment":    row.get("environment"),
            }

    history = get_state_history(tenant_id=effective_tenant, change_id=change_id)

    return {
        "ok":          True,
        "change_id":   change_id,
        "record":      record,
        "decisions":   decision_nodes,
        "deployment":  deploy_node,
        "correlation": correlation_node,
        "history":     history,
        "completeness": {
            "has_jira":            bool(record.get("jira_issue_key")),
            "has_pr":              bool(record.get("pr_repo")),
            "has_decision":        bool(record.get("rg_decision_ids")),
            "has_deploy":          bool(record.get("deploy_id")),
            "has_incident_traced": bool(record.get("incident_id")) and bool(record.get("deploy_id")),
            "lifecycle_closed":    record.get("lifecycle_state") == "CLOSED",
        },
    }


def fabric_health(*, tenant_id: str, days: int = 30) -> Dict[str, Any]:
    """Three-dimensional fabric health: completeness, integrity, friction."""
    from releasegate.storage.base import get_storage_backend, resolve_tenant_id
    from releasegate.storage.schema import init_db
    init_db()
    storage = get_storage_backend()
    _ensure_tables(storage)

    effective_tenant = resolve_tenant_id(tenant_id)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    def _cnt(cond: str, extra_params: tuple = ()) -> int:
        row = storage.fetchone(
            f"""SELECT COUNT(*) as cnt FROM {_TABLE} r
                LEFT JOIN cross_system_correlations c
                  ON c.tenant_id=r.tenant_id AND c.correlation_id=r.correlation_id
                WHERE r.tenant_id=? AND r.created_at>=? AND {cond}""",
            (effective_tenant, cutoff) + extra_params,
        )
        return int((row.get("cnt") or 0) if row else 0)

    total = _cnt("1=1")
    if total == 0:
        return {
            "ok": True, "tenant_id": effective_tenant, "window_days": days,
            "total_changes": 0,
            "completeness": {"pct": 100.0, "fully_linked": 0, "verdict": "HEALTHY"},
            "integrity":    {"orphan_deploys": 0, "missing_decisions": 0, "broken_chains": 0, "verdict": "OK"},
            "friction":     {"block_rate_pct": 0.0, "override_count": 0, "verdict": "LOW"},
            "health_verdict": "HEALTHY",
        }

    # Completeness: % of changes fully linked (jira + pr + decision + deploy)
    fully_linked = _cnt(
        "c.jira_issue_key IS NOT NULL AND c.pr_repo IS NOT NULL AND c.deploy_id IS NOT NULL"
    )
    completeness_pct = round(fully_linked / total * 100, 1)
    completeness_verdict = "HEALTHY" if completeness_pct >= 80 else ("DEGRADED" if completeness_pct >= 50 else "CRITICAL")

    # Integrity: broken chains
    orphan_deploys     = _cnt("c.deploy_id IS NOT NULL AND (c.jira_issue_key IS NULL OR c.pr_repo IS NULL)")
    missing_jira       = _cnt("c.pr_repo IS NOT NULL AND c.jira_issue_key IS NULL")
    broken_chains      = orphan_deploys + missing_jira
    integrity_verdict  = "OK" if broken_chains == 0 else ("WARNING" if broken_chains <= 3 else "CRITICAL")

    # Friction: block rate
    blocked      = _cnt("r.lifecycle_state = 'BLOCKED'")
    block_rate   = round(blocked / total * 100, 1)

    try:
        override_row = storage.fetchone(
            "SELECT COUNT(*) as cnt FROM audit_overrides WHERE tenant_id=? AND created_at>=?",
            (effective_tenant, cutoff),
        )
        override_count = int((override_row.get("cnt") or 0) if override_row else 0)
    except Exception:
        override_count = 0

    friction_verdict = "LOW" if block_rate < 5 else ("MEDIUM" if block_rate < 20 else "HIGH")

    by_state_rows = storage.fetchall(
        f"SELECT lifecycle_state, COUNT(*) as cnt FROM {_TABLE} WHERE tenant_id=? AND created_at>=? GROUP BY lifecycle_state",
        (effective_tenant, cutoff),
    ) or []
    by_state = {r.get("lifecycle_state"): int(r.get("cnt") or 0) for r in by_state_rows}

    overall = (
        "CRITICAL" if integrity_verdict == "CRITICAL" or completeness_verdict == "CRITICAL"
        else "DEGRADED" if any(v in ("DEGRADED", "WARNING", "MEDIUM", "HIGH")
                               for v in [completeness_verdict, integrity_verdict, friction_verdict])
        else "HEALTHY"
    )

    return {
        "ok":            True,
        "tenant_id":     effective_tenant,
        "window_days":   days,
        "total_changes": total,
        "by_state":      by_state,
        "completeness": {
            "pct":          completeness_pct,
            "fully_linked": fully_linked,
            "verdict":      completeness_verdict,
        },
        "integrity": {
            "orphan_deploys":    orphan_deploys,
            "missing_decisions": _cnt("c.deploy_id IS NOT NULL"),  # refined below
            "broken_chains":     broken_chains,
            "missing_jira":      missing_jira,
            "verdict":           integrity_verdict,
        },
        "friction": {
            "block_rate_pct": block_rate,
            "blocked_count":  blocked,
            "override_count": override_count,
            "verdict":        friction_verdict,
        },
        "health_verdict": overall,
    }
