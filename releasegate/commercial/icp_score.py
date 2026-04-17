"""ICP Scorer — Phase 9 Commercial Proof.

Scores a ReleaseGate tenant against the Ideal Customer Profile:

  "Engineering teams (10–100 devs) using Jira + GitHub, with compliance or
   audit pressure, deploying multiple times per week."

Score: 0–100 (weighted sum of signals). Band:
  STRONG   ≥ 70   → prioritise, offer white-glove onboarding
  MEDIUM   40–69  → nurture, show ROI calculator
  WEAK     < 40   → low priority, self-serve only

Signal weights
--------------
  has_jira_integration         20
  has_github_integration       15
  deploy_frequency_high        15
  team_size_in_icp_range       15
  enforcement_mode_strict      10
  has_audit_decisions           5
  has_overrides                 5
  traceability_coverage_high   10
  incident_linkage              5
                               ---
  max                         100
"""
from __future__ import annotations

from typing import Any, Dict

from releasegate.storage.db import get_db_connection


def _q_scalar(conn, sql: str, params: tuple = ()):
    cur = conn.cursor()
    cur.execute(sql, params)
    row = cur.fetchone()
    return row[0] if row else None


def score_tenant(
    *,
    tenant_id: str,
    team_size: int | None = None,
    deploys_per_week: float | None = None,
) -> Dict[str, Any]:
    """Return a full ICP score breakdown for a tenant.

    team_size and deploys_per_week can be passed explicitly if not stored
    in the database; otherwise the scorer infers them from activity.
    """
    conn = get_db_connection()
    try:
        return _compute(
            conn,
            tenant_id=tenant_id,
            team_size_hint=team_size,
            deploys_hint=deploys_per_week,
        )
    finally:
        conn.close()


def _compute(conn, *, tenant_id: str, team_size_hint, deploys_hint) -> Dict[str, Any]:
    signals: Dict[str, Dict[str, Any]] = {}

    # ── 1. Jira integration (any cross_system_correlations row has jira_issue_key)
    jira_count = _q_scalar(conn, """
        SELECT COUNT(*) FROM cross_system_correlations
        WHERE tenant_id = %s AND jira_issue_key IS NOT NULL AND jira_issue_key <> ''
        LIMIT 1
    """, (tenant_id,)) or 0
    signals["has_jira_integration"] = {
        "score": 20 if jira_count > 0 else 0, "max": 20,
        "value": jira_count > 0,
        "label": "Jira integration",
    }

    # ── 2. GitHub integration (pr_repo populated)
    github_count = _q_scalar(conn, """
        SELECT COUNT(*) FROM cross_system_correlations
        WHERE tenant_id = %s AND pr_repo IS NOT NULL AND pr_repo <> ''
        LIMIT 1
    """, (tenant_id,)) or 0
    signals["has_github_integration"] = {
        "score": 15 if github_count > 0 else 0, "max": 15,
        "value": github_count > 0,
        "label": "GitHub integration",
    }

    # ── 3. Deploy frequency (infer from change_records last 30 days)
    deploy_count_30d = _q_scalar(conn, """
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s
          AND created_at >= NOW() - INTERVAL '30 days'
          AND lifecycle_state IN ('DEPLOYED','VERIFIED','CLOSED')
    """, (tenant_id,)) or 0

    inferred_deploys_per_week = (deploy_count_30d / 30.0) * 7
    effective_dpw = deploys_hint if deploys_hint is not None else inferred_deploys_per_week
    deploy_high = effective_dpw >= 5  # ≥5 deploys/week = high frequency
    signals["deploy_frequency_high"] = {
        "score": 15 if deploy_high else (8 if effective_dpw >= 2 else 0),
        "max": 15,
        "value": round(effective_dpw, 1),
        "label": "Deploy frequency (per week)",
    }

    # ── 4. Team size in ICP range (10–100)
    # Infer from distinct actors in change_state_transitions
    distinct_actors = _q_scalar(conn, """
        SELECT COUNT(DISTINCT actor) FROM change_state_transitions
        WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '60 days'
    """, (tenant_id,)) or 0
    effective_size = team_size_hint if team_size_hint is not None else distinct_actors
    in_range = 10 <= effective_size <= 100
    signals["team_size_in_icp_range"] = {
        "score": 15 if in_range else (8 if effective_size > 5 else 0),
        "max": 15,
        "value": effective_size,
        "label": "Estimated team size",
    }

    # ── 5. Enforcement mode STRICT (highest governance signal)
    strict_count = _q_scalar(conn, """
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s AND enforcement_mode = 'STRICT'
        LIMIT 1
    """, (tenant_id,)) or 0
    signals["enforcement_mode_strict"] = {
        "score": 10 if strict_count > 0 else 0, "max": 10,
        "value": strict_count > 0,
        "label": "STRICT enforcement mode",
    }

    # ── 6. Has ReleaseGate audit decisions (compliance pressure signal)
    decision_count = _q_scalar(conn, """
        SELECT COUNT(*) FROM audit_decisions
        WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0
    signals["has_audit_decisions"] = {
        "score": 5 if decision_count > 0 else 0, "max": 5,
        "value": int(decision_count),
        "label": "Governance decisions declared (30d)",
    }

    # ── 7. Override/exception usage (friction = real governance pressure)
    override_count = _q_scalar(conn, """
        SELECT COUNT(*) FROM policy_overrides
        WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0
    signals["has_overrides"] = {
        "score": 5 if override_count > 0 else 0, "max": 5,
        "value": int(override_count),
        "label": "Policy overrides (30d)",
    }

    # ── 8. Traceability coverage (≥80% = high-compliance org)
    total = _q_scalar(conn, """
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0
    linked = _q_scalar(conn, """
        SELECT COUNT(DISTINCT cr.change_id)
        FROM change_records cr
        JOIN cross_system_correlations csc
          ON csc.correlation_id = cr.correlation_id AND csc.tenant_id = cr.tenant_id
        WHERE cr.tenant_id = %s
          AND cr.created_at >= NOW() - INTERVAL '30 days'
          AND csc.jira_issue_key IS NOT NULL AND csc.jira_issue_key <> ''
          AND csc.pr_repo        IS NOT NULL AND csc.pr_repo        <> ''
          AND csc.deploy_id      IS NOT NULL AND csc.deploy_id      <> ''
    """, (tenant_id,)) or 0
    coverage = (linked / total * 100) if total > 0 else 0
    signals["traceability_coverage_high"] = {
        "score": 10 if coverage >= 80 else (6 if coverage >= 50 else 0),
        "max": 10,
        "value": round(coverage, 1),
        "label": "Traceability coverage %",
    }

    # ── 9. Incident linkage (incident → deploy → hotfix chain exists)
    incident_count = _q_scalar(conn, """
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s
          AND lifecycle_state IN ('INCIDENT_ACTIVE','HOTFIX_IN_PROGRESS','VERIFIED','CLOSED')
          AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0
    signals["incident_linkage"] = {
        "score": 5 if incident_count > 0 else 0, "max": 5,
        "value": int(incident_count),
        "label": "Incident-linked changes (30d)",
    }

    # ── Total ─────────────────────────────────────────────────────────────────
    total_score = sum(s["score"] for s in signals.values())
    band = "STRONG" if total_score >= 70 else ("MEDIUM" if total_score >= 40 else "WEAK")

    recommendation = {
        "STRONG": (
            "High-priority prospect. Offer white-glove onboarding, "
            "a 2-week pilot with dedicated support, and a clear audit-compliance ROI story."
        ),
        "MEDIUM": (
            "Good fit but not fully activated. Share the ROI calculator, "
            "run a demo focused on their deploy chain, and propose a 30-day pilot."
        ),
        "WEAK": (
            "Early-stage fit. Not enough compliance/governance signals yet. "
            "Self-serve onboarding or wait until team scales."
        ),
    }[band]

    return {
        "tenant_id": tenant_id,
        "score": total_score,
        "band": band,
        "recommendation": recommendation,
        "signals": signals,
    }
