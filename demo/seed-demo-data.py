#!/usr/bin/env python3
"""Seed realistic governance demo data into the local ReleaseGate DB.

Produces enough blocked decisions, overrides, drift signals, and daily
rollups so that /overview shows real risk data instead of empty state.
"""
from __future__ import annotations

import argparse
import json
import random
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Blocked-decision templates — vary reason codes, repos, and environments
# ---------------------------------------------------------------------------

BLOCKED_TEMPLATES = [
    {
        "reason_code": "HIGH_RISK_APPROVAL_REQUIRED",
        "repo": "payments/release-service",
        "project_key": "PAYMENTS",
        "issue_prefix": "PAYMENTS",
        "environment": "PRODUCTION",
        "transition_id": "31",
        "workflow_id": "wf-release",
        "actor": "demo-deployer-1",
    },
    {
        "reason_code": "MISSING_APPROVAL",
        "repo": "payments/checkout-api",
        "project_key": "PAYMENTS",
        "issue_prefix": "PAYMENTS",
        "environment": "PRODUCTION",
        "transition_id": "31",
        "workflow_id": "wf-release",
        "actor": "demo-deployer-2",
    },
    {
        "reason_code": "POLICY_VIOLATION",
        "repo": "platform/identity-service",
        "project_key": "PLATFORM",
        "issue_prefix": "PLAT",
        "environment": "PRODUCTION",
        "transition_id": "41",
        "workflow_id": "wf-deploy-prod",
        "actor": "demo-deployer-3",
    },
    {
        "reason_code": "HIGH_RISK_APPROVAL_REQUIRED",
        "repo": "platform/notification-hub",
        "project_key": "PLATFORM",
        "issue_prefix": "PLAT",
        "environment": "STAGING",
        "transition_id": "21",
        "workflow_id": "wf-stage-promote",
        "actor": "demo-deployer-1",
    },
    {
        "reason_code": "MISSING_APPROVAL",
        "repo": "data/pipeline-orchestrator",
        "project_key": "DATA",
        "issue_prefix": "DATA",
        "environment": "PRODUCTION",
        "transition_id": "31",
        "workflow_id": "wf-release",
        "actor": "demo-deployer-4",
    },
    {
        "reason_code": "POLICY_VIOLATION",
        "repo": "payments/release-service",
        "project_key": "PAYMENTS",
        "issue_prefix": "PAYMENTS",
        "environment": "PRODUCTION",
        "transition_id": "31",
        "workflow_id": "wf-release",
        "actor": "demo-deployer-2",
    },
    {
        "reason_code": "HIGH_RISK_APPROVAL_REQUIRED",
        "repo": "data/pipeline-orchestrator",
        "project_key": "DATA",
        "issue_prefix": "DATA",
        "environment": "PRODUCTION",
        "transition_id": "31",
        "workflow_id": "wf-release",
        "actor": "demo-deployer-5",
    },
    {
        "reason_code": "MISSING_APPROVAL",
        "repo": "platform/identity-service",
        "project_key": "PLATFORM",
        "issue_prefix": "PLAT",
        "environment": "PRODUCTION",
        "transition_id": "41",
        "workflow_id": "wf-deploy-prod",
        "actor": "demo-deployer-3",
    },
]

ALLOWED_TEMPLATES = [
    {
        "repo": "payments/release-service",
        "project_key": "PAYMENTS",
        "issue_prefix": "PAYMENTS",
        "environment": "PRODUCTION",
        "transition_id": "31",
        "workflow_id": "wf-release",
    },
    {
        "repo": "payments/checkout-api",
        "project_key": "PAYMENTS",
        "issue_prefix": "PAYMENTS",
        "environment": "PRODUCTION",
        "transition_id": "31",
        "workflow_id": "wf-release",
    },
    {
        "repo": "platform/identity-service",
        "project_key": "PLATFORM",
        "issue_prefix": "PLAT",
        "environment": "STAGING",
        "transition_id": "21",
        "workflow_id": "wf-stage-promote",
    },
    {
        "repo": "platform/notification-hub",
        "project_key": "PLATFORM",
        "issue_prefix": "PLAT",
        "environment": "STAGING",
        "transition_id": "21",
        "workflow_id": "wf-stage-promote",
    },
    {
        "repo": "data/pipeline-orchestrator",
        "project_key": "DATA",
        "issue_prefix": "DATA",
        "environment": "PRODUCTION",
        "transition_id": "31",
        "workflow_id": "wf-release",
    },
]

OVERRIDE_REASONS = [
    "Emergency hotfix for payment processing outage",
    "Time-sensitive security patch — CVE-2025-31337",
    "Customer-facing SLA deadline, VP-approved",
    "Rollback required after failed canary deploy",
    "Compliance audit window closing, legal approved",
]


# ---------------------------------------------------------------------------
# Seed functions
# ---------------------------------------------------------------------------


def seed_decisions(conn: sqlite3.Connection, *, tenant_id: str) -> None:
    """Seed a mix of BLOCKED and ALLOWED decisions across multiple repos."""
    now = utc_now()
    rows = []

    # --- Blocked decisions (8 total, spread across last 48h) ---
    for idx, tpl in enumerate(BLOCKED_TEMPLATES):
        hours_ago = 48 - idx * 5  # spread over ~2 days
        created = now - timedelta(hours=hours_ago, minutes=random.randint(0, 30))
        decision_id = f"demo-blocked-{idx + 1}"
        issue_num = 320 + idx
        payload = {
            "reason_code": tpl["reason_code"],
            "input_snapshot": {
                "request": {
                    "issue_key": f"{tpl['issue_prefix']}-{issue_num}",
                    "transition_id": tpl["transition_id"],
                    "actor_account_id": tpl["actor"],
                    "environment": tpl["environment"],
                    "project_key": tpl["project_key"],
                    "context_overrides": {"workflow_id": tpl["workflow_id"]},
                }
            },
        }
        rows.append(
            (
                tenant_id,
                decision_id,
                f"ctx-{decision_id}",
                tpl["repo"],
                100 + idx,
                "BLOCKED",
                "demo-bundle-hash",
                "engine-v1",
                f"decision-hash-{decision_id}",
                f"input-hash-{decision_id}",
                "demo-policy-hash",
                f"replay-hash-{decision_id}",
                json.dumps(payload, separators=(",", ":"), sort_keys=True),
                iso(created),
                f"eval-{decision_id}",
            )
        )

    # --- Allowed decisions (12 total, for realistic override_rate denominator) ---
    actors = [
        "demo-deployer-1",
        "demo-deployer-2",
        "demo-deployer-3",
        "demo-deployer-4",
        "demo-deployer-5",
    ]
    for idx in range(12):
        tpl = ALLOWED_TEMPLATES[idx % len(ALLOWED_TEMPLATES)]
        hours_ago = 72 - idx * 5
        created = now - timedelta(hours=hours_ago, minutes=random.randint(0, 45))
        decision_id = f"demo-allowed-{idx + 1}"
        issue_num = 500 + idx
        payload = {
            "reason_code": "APPROVED",
            "input_snapshot": {
                "request": {
                    "issue_key": f"{tpl['issue_prefix']}-{issue_num}",
                    "transition_id": tpl["transition_id"],
                    "actor_account_id": actors[idx % len(actors)],
                    "environment": tpl["environment"],
                    "project_key": tpl["project_key"],
                    "context_overrides": {"workflow_id": tpl["workflow_id"]},
                }
            },
        }
        rows.append(
            (
                tenant_id,
                decision_id,
                f"ctx-{decision_id}",
                tpl["repo"],
                200 + idx,
                "ALLOWED",
                "demo-bundle-hash",
                "engine-v1",
                f"decision-hash-{decision_id}",
                f"input-hash-{decision_id}",
                "demo-policy-hash",
                f"replay-hash-{decision_id}",
                json.dumps(payload, separators=(",", ":"), sort_keys=True),
                iso(created),
                f"eval-{decision_id}",
            )
        )

    conn.executemany(
        """
        INSERT INTO audit_decisions (
            tenant_id, decision_id, context_id, repo, pr_number, release_status,
            policy_bundle_hash, engine_version, decision_hash, input_hash, policy_hash,
            replay_hash, full_decision_json, created_at, evaluation_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, decision_id) DO UPDATE SET
            release_status = excluded.release_status,
            full_decision_json = excluded.full_decision_json,
            created_at = excluded.created_at
        """,
        rows,
    )


def seed_overrides(conn: sqlite3.Connection, *, tenant_id: str) -> None:
    """Seed 5 override events: 3 active, 2 expired."""
    now = utc_now()
    rows = []

    override_specs = [
        # (decision_id, hours_ago, ttl_seconds, reason_index, is_active)
        ("demo-blocked-1", 6, 7200, 0, True),
        ("demo-blocked-2", 4, 3600, 1, True),
        ("demo-blocked-3", 3, 14400, 2, True),
        ("demo-blocked-5", 28, 3600, 3, False),  # expired
        ("demo-blocked-6", 36, 1800, 4, False),  # expired
    ]

    for idx, (decision_id, hours_ago, ttl, reason_idx, is_active) in enumerate(override_specs):
        created = now - timedelta(hours=hours_ago)
        if is_active:
            expires_at = now + timedelta(hours=2)
        else:
            expires_at = created + timedelta(seconds=ttl)  # already past

        blocked_idx = int(decision_id.split("-")[-1]) - 1
        tpl = BLOCKED_TEMPLATES[blocked_idx]
        issue_num = 320 + blocked_idx

        override_id = f"demo-ovr-{idx + 1}"
        rows.append(
            (
                tenant_id,
                override_id,
                tpl["repo"],
                100 + blocked_idx,
                f"{tpl['issue_prefix']}-{issue_num}",
                decision_id,
                tpl["actor"],
                OVERRIDE_REASONS[reason_idx],
                "transition",
                tpl["transition_id"],
                f"idem-{uuid.uuid4().hex}",
                "prev-hash",
                f"event-hash-{override_id}",
                ttl,
                iso(expires_at),
                tpl["actor"],
                "demo-approver-lead",
                iso(created),
            )
        )

    conn.executemany(
        """
        INSERT INTO audit_overrides (
            tenant_id, override_id, repo, pr_number, issue_key, decision_id,
            actor, reason, target_type, target_id, idempotency_key,
            previous_hash, event_hash, ttl_seconds, expires_at, requested_by,
            approved_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, override_id) DO UPDATE SET
            reason = excluded.reason,
            expires_at = excluded.expires_at,
            created_at = excluded.created_at
        """,
        rows,
    )


def seed_daily_rollups(conn: sqlite3.Connection, *, tenant_id: str) -> None:
    """Seed 14 days of rollups with realistic drift, override spikes, and alerts.

    The data tells a story a buyer can immediately read:
    - Integrity trending down over the past two weeks (governance tightening)
    - A visible drift signal on day -5 and day -2
    - An override spike on day -3
    - Pre-computed alerts embedded in details_json for the alerts panel
    """
    today = utc_now().date()
    rows = []

    # (days_ago, integrity, drift, decisions, overrides, blocked)
    day_profiles = [
        (13, 97.5, 0.02, 35, 0, 0),
        (12, 97.2, 0.02, 42, 0, 0),
        (11, 96.8, 0.03, 38, 1, 1),
        (10, 96.5, 0.03, 45, 1, 0),
        (9, 96.0, 0.04, 40, 1, 1),
        (8, 95.2, 0.05, 48, 1, 1),
        (7, 94.5, 0.06, 44, 2, 2),
        (6, 93.8, 0.08, 50, 2, 1),
        # Day -5: drift spike
        (5, 92.0, 0.22, 52, 2, 2),
        (4, 91.5, 0.15, 46, 2, 2),
        # Day -3: override spike
        (3, 90.2, 0.12, 40, 5, 3),
        # Day -2: drift spike again
        (2, 89.5, 0.25, 55, 3, 3),
        (1, 90.8, 0.10, 48, 2, 2),
        (0, 91.2, 0.08, 30, 2, 1),
    ]

    for days_ago, integrity, drift, decisions, overrides, blocked in day_profiles:
        day = today - timedelta(days=days_ago)
        date_utc = day.isoformat()
        override_rate = overrides / decisions if decisions > 0 else 0.0

        # Build details_json with alerts for notable days
        details: dict = {
            "override_abuse_index": round(override_rate * 1.2, 6),
            "decision_count": decisions,
            "override_count": overrides,
        }
        alerts = []

        if drift >= 0.15:
            alerts.append({
                "date_utc": date_utc,
                "severity": "medium",
                "code": "DRIFT_SPIKE",
                "title": "Drift index spiked vs 7-day baseline",
                "details": {
                    "today": round(drift, 6),
                    "baseline_7d": 0.05,
                },
            })

        if overrides >= 4:
            alerts.append({
                "date_utc": date_utc,
                "severity": "high",
                "code": "OVERRIDE_SPIKE",
                "title": "Override rate spiked vs 7-day baseline",
                "details": {
                    "today": round(override_rate, 6),
                    "baseline_7d": 0.03,
                    "override_count": overrides,
                    "decision_count": decisions,
                },
            })

        if blocked >= 3:
            alerts.append({
                "date_utc": date_utc,
                "severity": "medium",
                "code": "HIGH_BLOCK_RATE",
                "title": f"{blocked} releases blocked in a single day",
                "details": {
                    "blocked_count": blocked,
                    "decision_count": decisions,
                },
            })

        if alerts:
            details["alerts"] = alerts

        if drift >= 0.08:
            details["drift_breakdown"] = {
                "policy_version_mismatch": round(drift * 0.4, 4),
                "config_drift": round(drift * 0.35, 4),
                "schema_drift": round(drift * 0.25, 4),
            }

        rows.append(
            (
                tenant_id,
                date_utc,
                integrity,
                drift,
                override_rate,
                blocked,
                1,  # strict_mode_count
                overrides,
                decisions,
                iso(utc_now()),
                json.dumps(details, separators=(",", ":"), sort_keys=True),
            )
        )

    conn.executemany(
        """
        INSERT INTO governance_daily_metrics (
            tenant_id, date_utc, integrity_score, drift_index, override_rate, blocked_count,
            strict_mode_count, override_count, decision_count, computed_at, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, date_utc) DO UPDATE SET
            integrity_score = excluded.integrity_score,
            drift_index = excluded.drift_index,
            override_rate = excluded.override_rate,
            blocked_count = excluded.blocked_count,
            strict_mode_count = excluded.strict_mode_count,
            override_count = excluded.override_count,
            decision_count = excluded.decision_count,
            computed_at = excluded.computed_at,
            details_json = excluded.details_json
        """,
        rows,
    )


def seed_simulation(conn: sqlite3.Connection, *, tenant_id: str) -> None:
    """Seed a realistic historical simulation run so /onboarding shows real value."""
    now = utc_now()
    run_id = str(uuid.uuid4())
    result = {
        "tenant_id": tenant_id,
        "lookback_days": 30,
        "total_transitions": 47,
        "allowed": 35,
        "blocked": 8,
        "blocked_pct": 17.02,
        "override_required": 4,
        "starter_pack": "conservative",
        "insights": {
            "high_risk_releases": 6,
            "missing_approvals": 4,
            "unmapped_transitions": 2,
        },
        "summary": (
            "Analyzed 47 recent transitions. 6 high-risk releases detected, "
            "4 missing required approvals, and 2 unmapped transitions. "
            "17% of transitions would have been blocked under the starter policy pack."
        ),
        "risk_distribution": {
            "low": 29,
            "medium": 10,
            "high": 8,
        },
        "ran_at": iso(now),
        "has_run": True,
    }
    conn.execute(
        """
        INSERT OR REPLACE INTO tenant_simulation_runs (
            tenant_id, run_id, lookback_days, result_json,
            total_transitions, blocked, blocked_pct, override_required,
            risk_distribution_json, ran_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            run_id,
            30,
            json.dumps(result, separators=(",", ":"), sort_keys=True),
            47,
            8,
            17.02,
            4,
            json.dumps(result["risk_distribution"], separators=(",", ":")),
            iso(now),
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed demo governance data into the local ReleaseGate DB",
    )
    parser.add_argument("--tenant-id", default="demo", help="Tenant ID to seed")
    args = parser.parse_args()

    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        seed_decisions(conn, tenant_id=args.tenant_id)
        seed_overrides(conn, tenant_id=args.tenant_id)
        seed_daily_rollups(conn, tenant_id=args.tenant_id)
        seed_simulation(conn, tenant_id=args.tenant_id)
        conn.commit()
    finally:
        conn.close()

    print(f"Seeded demo data for tenant '{args.tenant_id}' into {DB_PATH}")
    print("  - 8 blocked decisions (HIGH_RISK_APPROVAL_REQUIRED, MISSING_APPROVAL, POLICY_VIOLATION)")
    print("  - 12 allowed decisions (realistic override-rate denominator)")
    print("  - 5 override events (3 active, 2 expired)")
    print("  - 14 days of daily rollups with drift spikes, override spikes, and alerts")
    print("  - 1 simulation run (47 transitions, 8 blocked, 6 high-risk, 4 missing approvals)")


if __name__ == "__main__":
    main()
