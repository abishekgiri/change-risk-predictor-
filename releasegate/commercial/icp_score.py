"""ICP Scorer — Phase 9 Commercial Proof.

Scores a ReleaseGate tenant against the Ideal Customer Profile:

  "Engineering teams (10–100 devs) using Jira + GitHub, with compliance or
   audit pressure, deploying multiple times per week across multiple envs."

Score: 0–100 (weighted sum of signals). Band:
  STRONG   ≥ 70
  MEDIUM   40–69
  WEAK     < 40

Signal weights
--------------
  jira_intensity             20
  github_integration         10
  deploy_frequency           15
  multi_environment          15
  team_size_in_range         10
  compliance_pressure        15
  incident_frequency         10
  override_usage              5
                             ---
  max                        100
"""
from __future__ import annotations

from typing import Any, Dict

from releasegate.storage.db import get_db_connection, window_predicate


def _q_scalar(conn, sql: str, params: tuple = ()):
    """Run a scalar query. On missing-table errors (fresh dev DB), return None
    so the overall ICP score still computes from whatever tables are live."""
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        row = cur.fetchone()
        return row[0] if row else None
    except Exception:
        # Best-effort: rollback any aborted tx on Postgres so subsequent
        # queries on the same connection don't cascade-fail.
        try:
            conn.rollback()
        except Exception:
            pass
        return None


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
    dialect = getattr(conn, "dialect", "sqlite")
    w30  = window_predicate(dialect, "created_at", 30)
    w60  = window_predicate(dialect, "created_at", 60)
    signals: Dict[str, Dict[str, Any]] = {}

    # ── 1. Jira intensity ────────────────────────────────────────────────────
    jira_keys = int(_q_scalar(conn, f"""
        SELECT COUNT(DISTINCT jira_issue_key)
        FROM cross_system_correlations
        WHERE tenant_id = %s
          AND jira_issue_key IS NOT NULL AND jira_issue_key <> ''
          AND {w30}
    """, (tenant_id,)) or 0)
    signals["jira_intensity"] = {
        "score": 20 if jira_keys >= 10 else (12 if jira_keys >= 3 else (5 if jira_keys >= 1 else 0)),
        "max": 20,
        "value": jira_keys,
        "label": f"Unique Jira keys linked (30d): {jira_keys} — needs 10+ for full score",
    }

    # ── 2. GitHub integration ────────────────────────────────────────────────
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

    # ── 3. Deploy frequency ──────────────────────────────────────────────────
    deploy_count_30d = int(_q_scalar(conn, f"""
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s
          AND {w30}
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

    # ── 4. Multi-environment ──────────────────────────────────────────────────
    env_count = int(_q_scalar(conn, f"""
        SELECT COUNT(DISTINCT environment)
        FROM change_records
        WHERE tenant_id = %s
          AND environment IS NOT NULL AND environment <> ''
          AND {w30}
    """, (tenant_id,)) or 0)
    signals["multi_environment"] = {
        "score": 15 if env_count >= 3 else (10 if env_count == 2 else (4 if env_count == 1 else 0)),
        "max": 15,
        "value": env_count,
        "label": f"{env_count} deployment environment(s) — 3+ (prod/staging/dev) = mature release process",
    }

    # ── 5. Team size in ICP range ────────────────────────────────────────────
    distinct_actors = int(_q_scalar(conn, f"""
        SELECT COUNT(DISTINCT actor) FROM change_state_transitions
        WHERE tenant_id = %s AND {w60}
    """, (tenant_id,)) or 0)
    effective_size = team_size_hint if team_size_hint is not None else distinct_actors
    signals["team_size_in_range"] = {
        "score": 10 if 10 <= effective_size <= 100 else (5 if effective_size > 5 else 0),
        "max": 10,
        "value": effective_size,
        "label": f"Estimated team size: {effective_size} — target range is 10–100",
    }

    # ── 6. Compliance pressure ───────────────────────────────────────────────
    strict_count = int(_q_scalar(conn, """
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s AND enforcement_mode = 'STRICT'
    """, (tenant_id,)) or 0)
    decision_count = int(_q_scalar(conn, f"""
        SELECT COUNT(*) FROM audit_decisions
        WHERE tenant_id = %s AND {w30}
    """, (tenant_id,)) or 0)
    has_strict    = strict_count > 0
    has_decisions = decision_count >= 5
    signals["compliance_pressure"] = {
        "score": 15 if (has_strict and has_decisions) else (8 if (has_strict or decision_count > 0) else 0),
        "max": 15,
        "value": {"strict_mode": has_strict, "decisions_30d": decision_count},
        "label": (
            f"STRICT enforcement: {'yes' if has_strict else 'no'}, "
            f"{decision_count} governance decisions (30d) — both required for full score"
        ),
    }

    # ── 7. Incident frequency ────────────────────────────────────────────────
    incident_count = int(_q_scalar(conn, f"""
        SELECT COUNT(*) FROM change_records
        WHERE tenant_id = %s
          AND lifecycle_state IN ('INCIDENT_ACTIVE','HOTFIX_IN_PROGRESS','VERIFIED','CLOSED')
          AND {w30}
    """, (tenant_id,)) or 0)
    signals["incident_frequency"] = {
        "score": 10 if incident_count >= 3 else (6 if incident_count >= 1 else 0),
        "max": 10,
        "value": incident_count,
        "label": f"{incident_count} incident-linked changes (30d) — incidents = deploy risk is real",
    }

    # ── 8. Override / exception usage ────────────────────────────────────────
    override_count = int(_q_scalar(conn, f"""
        SELECT COUNT(*) FROM policy_overrides
        WHERE tenant_id = %s AND {w30}
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
