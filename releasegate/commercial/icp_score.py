"""ICP Scorer — Phase 9 Commercial Proof.

Scores a ReleaseGate tenant against the Ideal Customer Profile:

  "Engineering teams (10–100 devs) using Jira + GitHub, with compliance or
   audit pressure, deploying multiple times per week across multiple envs."

Score: 0–100 (weighted sum of signals). Band:
  STRONG   ≥ 70   → prioritise, offer white-glove onboarding
  MEDIUM   40–69  → nurture, show ROI calculator
  WEAK     < 40   → low priority, self-serve only

Signal design: quality over quantity.
Each signal has a clear business reason. If a signal can't be explained in
one sentence to a prospect, it doesn't belong here.

Signal weights
--------------
  jira_intensity             20   (unique Jira keys, not just "has Jira")
  github_integration         10
  deploy_frequency           15   (≥5/wk = high-complexity team)
  multi_environment          15   (prod + staging = real release process)
  team_size_in_range         10   (10–100 devs = feels the pain, can buy)
  compliance_pressure        15   (STRICT mode + audit decisions declared)
  incident_frequency         10   (incidents = deployment risk is real)
  override_usage              5   (overrides = governance friction = need)
                             ---
  max                        100
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
    """Return a full ICP score breakdown for a tenant."""
    conn = get_db_connection()
    try:
        return _compute(conn, tenant_id=tenant_id, team_size_hint=team_size, deploys_hint=deploys_per_week)
    finally:
        conn.close()


def _compute(conn, *, tenant_id: str, team_size_hint, deploys_hint) -> Dict[str, Any]:
    signals: Dict[str, Dict[str, Any]] = {}

    # ── 1. Jira intensity — unique Jira keys (not just "has Jira") ────────────
    # A team with 1 Jira key is experimenting. 10+ means it's embedded in workflow.
    jira_keys = int(_q_scalar(conn, """
        SELECT COUNT(DISTINCT jira_issue_key)
        FROM cross_system_correlations
        WHERE tenant_id = %s
          AND jira_issue_key IS NOT NULL AND jira_issue_key <> ''
          AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0)
    signals["jira_intensity"] = {
        "score": 20 if jira_keys >= 10 else (12 if jira_keys >= 3 else (5 if jira_keys >= 1 else 0)),
        "max": 20,
        "value": jira_keys,
        "label": f"Unique Jira keys linked (30d): {jira_keys} — needs 10+ for full score",
    }

    # ── 2. GitHub integration — PRs linked ───────────────────────────────────
    pr_count = int(_q_scalar(conn, """
        SELECT COUNT(DISTINCT pr_repo)
        FROM cross_system_correlations
        WHERE tenant_id = %s AND pr_repo IS NOT NULL AND pr_repo <> ''
    """, (tenant_id,)) or 0)
    signals["github_integration"] = {
        "score": 10 if pr_count > 0 else 0,
        "max": 10,
        "value": pr_count,
        "label": f"{pr_count} GitHub repo(s) connected",
    }

    # ── 3. Deploy frequency — inferred from change records ───────────────────
    deploy_count_30d = int(_q_scalar(conn, """
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s
          AND created_at >= NOW() - INTERVAL '30 days'
          AND lifecycle_state IN ('DEPLOYED','VERIFIED','CLOSED')
    """, (tenant_id,)) or 0)
    inferred_dpw = (deploy_count_30d / 30.0) * 7
    effective_dpw = deploys_hint if deploys_hint is not None else inferred_dpw
    signals["deploy_frequency"] = {
        "score": 15 if effective_dpw >= 5 else (9 if effective_dpw >= 2 else (3 if effective_dpw >= 1 else 0)),
        "max": 15,
        "value": round(effective_dpw, 1),
        "label": f"~{round(effective_dpw, 1)} deploys/week — ≥5/wk = high-complexity team (full score)",
    }

    # ── 4. Multi-environment deploys — strongest "real release process" signal
    # Count distinct environment values across change records
    env_count = int(_q_scalar(conn, """
        SELECT COUNT(DISTINCT environment)
        FROM change_records
        WHERE tenant_id = %s
          AND environment IS NOT NULL AND environment <> ''
          AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0)
    signals["multi_environment"] = {
        "score": 15 if env_count >= 3 else (10 if env_count == 2 else (4 if env_count == 1 else 0)),
        "max": 15,
        "value": env_count,
        "label": f"{env_count} deployment environment(s) — 3+ (prod/staging/dev) = mature release process",
    }

    # ── 5. Team size in ICP range (10–100) ────────────────────────────────────
    distinct_actors = int(_q_scalar(conn, """
        SELECT COUNT(DISTINCT actor) FROM change_state_transitions
        WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '60 days'
    """, (tenant_id,)) or 0)
    effective_size = team_size_hint if team_size_hint is not None else distinct_actors
    signals["team_size_in_range"] = {
        "score": 10 if 10 <= effective_size <= 100 else (5 if effective_size > 5 else 0),
        "max": 10,
        "value": effective_size,
        "label": f"Estimated team size: {effective_size} — target range is 10–100",
    }

    # ── 6. Compliance pressure — STRICT mode + audit decisions ───────────────
    # Both signals must be present: they chose STRICT enforcement AND are
    # actually declaring decisions. That's a team that has compliance pain.
    strict_count = int(_q_scalar(conn, """
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s AND enforcement_mode = 'STRICT'
    """, (tenant_id,)) or 0)
    decision_count = int(_q_scalar(conn, """
        SELECT COUNT(*) FROM audit_decisions
        WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0)
    has_strict   = strict_count > 0
    has_decisions = decision_count >= 5  # ≥5 decisions = real usage, not a test
    signals["compliance_pressure"] = {
        "score": 15 if (has_strict and has_decisions) else (8 if (has_strict or decision_count > 0) else 0),
        "max": 15,
        "value": {"strict_mode": has_strict, "decisions_30d": decision_count},
        "label": (
            f"STRICT enforcement: {'yes' if has_strict else 'no'}, "
            f"{decision_count} governance decisions (30d) — both required for full score"
        ),
    }

    # ── 7. Incident frequency — incidents are real deployment risk ────────────
    incident_count = int(_q_scalar(conn, """
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s
          AND lifecycle_state IN ('INCIDENT_ACTIVE','HOTFIX_IN_PROGRESS','VERIFIED','CLOSED')
          AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0)
    signals["incident_frequency"] = {
        "score": 10 if incident_count >= 3 else (6 if incident_count >= 1 else 0),
        "max": 10,
        "value": incident_count,
        "label": f"{incident_count} incident-linked changes (30d) — incidents = deploy risk is real",
    }

    # ── 8. Override / exception usage ─────────────────────────────────────────
    override_count = int(_q_scalar(conn, """
        SELECT COUNT(*) FROM policy_overrides
        WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '30 days'
    """, (tenant_id,)) or 0)
    signals["override_usage"] = {
        "score": 5 if override_count > 0 else 0,
        "max": 5,
        "value": override_count,
        "label": f"{override_count} policy overrides (30d) — overrides signal governance friction",
    }

    # ── Total ─────────────────────────────────────────────────────────────────
    total_score = sum(s["score"] for s in signals.values())
    band = "STRONG" if total_score >= 70 else ("MEDIUM" if total_score >= 40 else "WEAK")

    recommendation = {
        "STRONG": (
            "High-priority prospect. Offer white-glove onboarding and a 2-week "
            "paid pilot. Lead with the compliance + incident risk story."
        ),
        "MEDIUM": (
            "Good fit, not fully activated. Open /proof in a call and show their "
            "live traceability number. Propose a 30-day pilot."
        ),
        "WEAK": (
            "Early-stage fit. Not enough compliance or deploy-complexity signals. "
            "Self-serve or wait until team scales past 10 engineers."
        ),
    }[band]

    # Surface the two highest-value gaps so sales knows exactly what to ask about
    gaps = sorted(
        [
            {"signal": k, "gap": s["max"] - s["score"], "label": s["label"]}
            for k, s in signals.items()
            if s["score"] < s["max"]
        ],
        key=lambda x: -x["gap"],
    )[:2]

    return {
        "tenant_id": tenant_id,
        "score": total_score,
        "band": band,
        "recommendation": recommendation,
        "top_gaps": gaps,
        "signals": signals,
    }
