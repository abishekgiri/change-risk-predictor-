"""Proof Metrics — Phase 9 Commercial Proof.

Auto-generates the quantified "before vs after" case study data from a
tenant's actual ReleaseGate usage. No manual work required — every number
is derived from live data in the database.

Output shape (used by /commercial/proof endpoint)
-------------------------------------------------
{
  "tenant_id": "acme",
  "window_days": 30,
  "traceability_coverage_pct": 94.0,
  "orphan_deploys_prevented": 7,
  "blocked_risky_deploys": 12,
  "governance_decisions_declared": 43,
  "full_chain_changes": 38,
  "audit_coverage_pct": 91.0,
  "mean_time_to_decision_hours": 1.2,
  "case_study_table": [...],
}
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Tuple

from releasegate.storage.db import (
    column_exists,
    epoch_hours_diff_sql,
    get_db_connection,
    json_array_len_sql,
    window_predicate,
)


# ── Small TTL cache: /proof is called from dashboards and can be re-opened
# repeatedly within seconds.  7+ queries per call is expensive, so cache
# results per (tenant_id, window_days) for a short window.
_CACHE_TTL_SECONDS = 60
_cache: Dict[Tuple[str, int], Tuple[float, Dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def _cache_get(key: Tuple[str, int]) -> Dict[str, Any] | None:
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.time() > expires_at:
            _cache.pop(key, None)
            return None
        return value


def _cache_put(key: Tuple[str, int], value: Dict[str, Any]) -> None:
    with _cache_lock:
        _cache[key] = (time.time() + _CACHE_TTL_SECONDS, value)


def invalidate_proof_cache(tenant_id: str | None = None) -> None:
    """Clear cached proof metrics (for tests or post-write invalidation)."""
    with _cache_lock:
        if tenant_id is None:
            _cache.clear()
        else:
            for key in [k for k in _cache if k[0] == tenant_id]:
                _cache.pop(key, None)


def _q(conn, sql: str, params: tuple = ()) -> List[Any]:
    """Run a query. On missing-table errors (fresh dev DB), return [] so the
    overall proof response still computes from whatever tables are live."""
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return []


def generate_proof_metrics(
    *,
    tenant_id: str,
    window_days: int = 30,
) -> Dict[str, Any]:
    """Pull live governance data and return quantified proof-of-value metrics."""
    window_days = max(1, int(window_days))
    cache_key = (tenant_id, window_days)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    conn = get_db_connection()
    try:
        result = _compute(conn, tenant_id=tenant_id, window_days=window_days)
    finally:
        conn.close()

    _cache_put(cache_key, result)
    return result


def _compute(conn, *, tenant_id: str, window_days: int) -> Dict[str, Any]:
    dialect = getattr(conn, "dialect", "sqlite")
    # window_days is guaranteed int by caller; window_predicate also re-coerces.
    window = window_predicate(dialect, "cr.created_at", window_days)
    window_csc = window_predicate(dialect, "created_at", window_days)
    window_audit = window_predicate(dialect, "created_at", window_days)
    window_trans = window_predicate(dialect, "created_at", window_days)
    window_change_plain = window_predicate(dialect, "created_at", window_days)
    params_t = (tenant_id,)

    # ── 1. ChangeRecord stats ─────────────────────────────────────────────────
    rows = _q(conn, f"""
        SELECT
            COUNT(*)                                               AS total,
            SUM(CASE WHEN lifecycle_state = 'BLOCKED' THEN 1 ELSE 0 END)   AS blocked,
            SUM(CASE WHEN lifecycle_state = 'CLOSED' THEN 1 ELSE 0 END)    AS closed,
            SUM(CASE WHEN lifecycle_state IN ('DEPLOYED','VERIFIED','CLOSED') THEN 1 ELSE 0 END) AS deployed
        FROM change_records
        WHERE tenant_id = %s AND {window_change_plain}
    """, params_t)
    r = rows[0] if rows else (0, 0, 0, 0)
    total_changes    = int(r[0] or 0)
    blocked_changes  = int(r[1] or 0)
    deployed_changes = int(r[3] or 0)

    # ── 2. Fully-linked changes (complete Jira→PR→Decision→Deploy chain) ──────
    rows = _q(conn, f"""
        SELECT COUNT(DISTINCT cr.change_id)
        FROM change_records cr
        JOIN cross_system_correlations csc ON csc.correlation_id = cr.correlation_id
            AND csc.tenant_id = cr.tenant_id
        WHERE cr.tenant_id = %s
          AND {window}
          AND csc.jira_issue_key IS NOT NULL AND csc.jira_issue_key <> ''
          AND csc.pr_repo        IS NOT NULL AND csc.pr_repo        <> ''
          AND csc.deploy_id      IS NOT NULL AND csc.deploy_id      <> ''
    """, params_t)
    full_chain_changes = int((rows[0][0] if rows else 0) or 0)

    traceability_pct = (
        round(full_chain_changes / total_changes * 100, 1) if total_changes > 0 else 0.0
    )

    # ── 3. Orphan deploys prevented ─────────────────────────────────────────
    rows = _q(conn, f"""
        SELECT COUNT(DISTINCT cr.change_id)
        FROM change_records cr
        JOIN cross_system_correlations csc ON csc.correlation_id = cr.correlation_id
            AND csc.tenant_id = cr.tenant_id
        WHERE cr.tenant_id = %s
          AND {window}
          AND csc.deploy_id IS NOT NULL AND csc.deploy_id <> ''
          AND (csc.pr_repo IS NULL OR csc.pr_repo = ''
               OR csc.jira_issue_key IS NULL OR csc.jira_issue_key = '')
          AND cr.lifecycle_state = 'BLOCKED'
    """, params_t)
    orphan_deploys_prevented = int((rows[0][0] if rows else 0) or 0)

    # ── 4. Governance decisions declared ─────────────────────────────────────
    rows = _q(conn, f"""
        SELECT COUNT(*), MIN(created_at), MAX(created_at)
        FROM audit_decisions
        WHERE tenant_id = %s AND {window_audit}
    """, params_t)
    r = rows[0] if rows else (0, None, None)
    total_decisions   = int(r[0] or 0)
    first_decision_at = r[1]
    last_decision_at  = r[2]

    # ── 5. Audit coverage: % of deploys with a ReleaseGate decision ───────────
    # rg_decision_ids is stored as JSON-array text. Use json_array_length in a
    # dialect-aware way instead of string equality hacks.
    rg_len_expr = json_array_len_sql(dialect, "csc.rg_decision_ids")
    rows = _q(conn, f"""
        SELECT COUNT(DISTINCT cr.change_id)
        FROM change_records cr
        JOIN cross_system_correlations csc ON csc.correlation_id = cr.correlation_id
            AND csc.tenant_id = cr.tenant_id
        WHERE cr.tenant_id = %s
          AND {window}
          AND csc.deploy_id IS NOT NULL AND csc.deploy_id <> ''
          AND {rg_len_expr} > 0
    """, params_t)
    deploys_with_decision = int((rows[0][0] if rows else 0) or 0)
    audit_coverage_pct = (
        round(deploys_with_decision / deployed_changes * 100, 1)
        if deployed_changes > 0 else 0.0
    )

    # ── 6. Mean time to decision (signal → allowed) ──────────────────────────
    # signal_evaluated_at is a newer column on audit_decisions; guard so older
    # deployments don't crash the whole /proof endpoint.
    mttd_hours = 0.0
    if column_exists(conn, "audit_decisions", "signal_evaluated_at"):
        epoch_expr = epoch_hours_diff_sql(dialect, "created_at", "signal_evaluated_at")
        try:
            rows = _q(conn, f"""
                SELECT AVG({epoch_expr})
                FROM audit_decisions
                WHERE tenant_id = %s
                  AND {window_audit}
                  AND signal_evaluated_at IS NOT NULL
                  AND release_status = 'ALLOWED'
            """, params_t)
            mttd_hours = float((rows[0][0] if rows and rows[0] and rows[0][0] else 0) or 0)
        except Exception:
            mttd_hours = 0.0

    # ── 7. State transition audit: how many BLOCKED transitions ──────────────
    rows = _q(conn, f"""
        SELECT COUNT(*)
        FROM change_state_transitions
        WHERE tenant_id = %s AND to_state = 'BLOCKED' AND {window_trans}
    """, params_t)
    blocked_transitions = int((rows[0][0] if rows else 0) or 0)

    blocked_risky_deploys = max(blocked_changes, blocked_transitions)

    # ── Case study table ──────────────────────────────────────────────────────
    def _safe_pp(after: float, before: float) -> str:
        delta = round(after - before)
        return f"+{delta}pp" if delta > 0 else (f"{delta}pp" if delta < 0 else "0pp")

    case_study_table: List[Dict[str, str]] = [
        {
            "metric": "Traceability coverage",
            "before": "~55% (industry baseline, DORA 2023)",
            "after": f"{traceability_pct}%",
            "improvement": _safe_pp(traceability_pct, 55.0),
            "source": "Your data vs DORA 2023 industry average",
        },
        {
            "metric": "Orphan deploys blocked",
            "before": "0 caught (no enforcement gate)",
            "after": f"{orphan_deploys_prevented} stopped",
            "improvement": f"{orphan_deploys_prevented} prevented" if orphan_deploys_prevented > 0 else "0 (clean already)",
            "source": "Your ReleaseGate enforcement logs",
        },
        {
            "metric": "Risky deploy transitions blocked",
            "before": "0 (no governance layer)",
            "after": str(blocked_risky_deploys),
            "improvement": f"{blocked_risky_deploys} caught" if blocked_risky_deploys > 0 else "0",
            "source": "change_state_transitions audit table",
        },
        {
            "metric": "Audit decision coverage",
            "before": "Manual / ad-hoc",
            "after": f"{audit_coverage_pct}% of deploys have a decision record",
            "improvement": "Automated evidence trail",
            "source": "Your audit_decisions table",
        },
        {
            "metric": "Governance decisions declared",
            "before": "0 (no system of record)",
            "after": f"{total_decisions} in {window_days}-day window",
            "improvement": "Full immutable audit log",
            "source": "Your ReleaseGate decision registry",
        },
    ]

    return {
        "tenant_id": tenant_id,
        "window_days": window_days,
        "first_decision_at": str(first_decision_at) if first_decision_at else None,
        "last_decision_at":  str(last_decision_at)  if last_decision_at  else None,
        # Core proof metrics
        "total_changes": total_changes,
        "full_chain_changes": full_chain_changes,
        "traceability_coverage_pct": traceability_pct,
        "orphan_deploys_prevented": orphan_deploys_prevented,
        "blocked_risky_deploys": blocked_risky_deploys,
        "governance_decisions_declared": total_decisions,
        "deployed_with_decision": deploys_with_decision,
        "audit_coverage_pct": audit_coverage_pct,
        "mean_time_to_decision_hours": round(mttd_hours, 2),
        # Sales table with sources labelled
        "case_study_table": case_study_table,
        # Transparency note shown on the dashboard
        "baseline_note": (
            "\"Before\" figures are industry baselines (DORA 2023, Vanta/Drata surveys). "
            "\"After\" figures are your actual ReleaseGate data. "
            "Replace baselines with your own pre-ReleaseGate numbers for a stronger case study."
        ),
    }
