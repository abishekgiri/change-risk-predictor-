#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def seed_decisions(conn: sqlite3.Connection, *, tenant_id: str) -> None:
    now = utc_now()
    rows = []
    for index in range(8):
        created = now - timedelta(hours=(8 - index) * 3)
        blocked = index in {1, 5}
        decision_id = f"demo-dec-{index + 1}"
        release_status = "BLOCKED" if blocked else "ALLOWED"
        reason_code = "HIGH_RISK_APPROVAL_REQUIRED" if blocked else "APPROVED"
        payload = {
            "reason_code": reason_code,
            "input_snapshot": {
                "request": {
                    "issue_key": f"PAYMENTS-{320 + index}",
                    "transition_id": "31",
                    "actor_account_id": "demo-user",
                    "environment": "PRODUCTION",
                    "project_key": "PAYMENTS",
                    "context_overrides": {"workflow_id": "wf-release"},
                }
            },
        }
        rows.append(
            (
                tenant_id,
                decision_id,
                f"ctx-{decision_id}",
                "payments/release-service",
                100 + index,
                release_status,
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
    now = utc_now()
    rows = []
    for offset, decision_id in enumerate(["demo-dec-2", "demo-dec-6"]):
        created = now - timedelta(hours=(offset + 1) * 2)
        override_id = f"demo-ovr-{offset + 1}"
        rows.append(
            (
                tenant_id,
                override_id,
                "payments/release-service",
                100 + offset,
                f"PAYMENTS-{400 + offset}",
                decision_id,
                "demo-operator",
                "Emergency demo override",
                "transition",
                "31",
                f"idem-{uuid.uuid4().hex}",
                "prev-hash",
                f"event-hash-{override_id}",
                3600,
                iso(created + timedelta(hours=1)),
                "demo-requester",
                "demo-approver",
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
            created_at = excluded.created_at
        """,
        rows,
    )


def seed_daily_rollups(conn: sqlite3.Connection, *, tenant_id: str) -> None:
    today = utc_now().date()
    rows = []
    for i in range(7):
        date_utc = (today - timedelta(days=6 - i)).isoformat()
        integrity = 96.0 - (i * 0.8)
        drift = max(0.0, 0.02 + i * 0.005)
        decisions = 40 + i * 3
        overrides = 1 if i < 4 else 2
        blocked = 2 if i in {1, 5} else 1
        rows.append(
            (
                tenant_id,
                date_utc,
                integrity,
                drift,
                float(overrides / decisions),
                int(blocked),
                1,
                int(overrides),
                int(decisions),
                iso(utc_now()),
                "{}",
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed demo governance data into the local ReleaseGate DB")
    parser.add_argument("--tenant-id", default="demo", help="Tenant ID to seed")
    args = parser.parse_args()

    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        seed_decisions(conn, tenant_id=args.tenant_id)
        seed_overrides(conn, tenant_id=args.tenant_id)
        seed_daily_rollups(conn, tenant_id=args.tenant_id)
        conn.commit()
    finally:
        conn.close()

    print(f"Seeded demo data for tenant '{args.tenant_id}' into {DB_PATH}")


if __name__ == "__main__":
    main()
