#!/usr/bin/env python3
"""Seed the ReleaseGate demo database with realistic fixture data.

Creates two demo tenants:
  demo       – healthy tenant: checkpoints, allowed releases, one blocked deploy
  demo-risk  – at-risk tenant: stale signal, no checkpoint, several blocked deploys

Run via:  python3 scripts/seed_demo.py
The script is idempotent; re-running it is safe.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone

DB_PATH = os.getenv("RELEASEGATE_SQLITE_PATH", "/data/releasegate.db")


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(offset_hours: float = 0) -> str:
    return (_now() + timedelta(hours=offset_hours)).isoformat()


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def ensure_schema(con: sqlite3.Connection) -> None:
    """Initialize schema via the ReleaseGate init_db routine."""
    sys.path.insert(0, "/app")
    try:
        from releasegate.storage.schema import init_db
        init_db()
        print("  schema initialised")
    except Exception as exc:
        print(f"  schema init skipped ({exc}); assuming already present")


def seed_decisions(con: sqlite3.Connection, tenant_id: str, scenarios: list[dict]) -> None:
    for s in scenarios:
        did = str(uuid.uuid4())
        payload = json.dumps({
            "repo": s["repo"],
            "pr_number": s.get("pr_number"),
            "actor": s.get("actor", "alice"),
            "workflow_id": s.get("workflow_id"),
        })
        policy_hash = _sha256(f"policy::{tenant_id}::{s['repo']}")
        input_hash  = _sha256(payload)
        decision_hash = _sha256(f"{did}::{s['status']}::{input_hash}")
        replay_hash   = _sha256(f"replay::{did}")
        try:
            con.execute(
                """INSERT OR IGNORE INTO audit_decisions
                   (id, tenant_id, repo, release_status, computed_at,
                    policy_hash, input_hash, decision_hash, replay_hash,
                    decision_payload, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    did, tenant_id, s["repo"], s["status"], _ts(s.get("age_offset_hours", 0)),
                    policy_hash, input_hash, decision_hash, replay_hash,
                    payload, _ts(s.get("age_offset_hours", 0)),
                ),
            )
        except Exception as exc:
            print(f"    decision insert skipped: {exc}")
    con.commit()
    print(f"  seeded {len(scenarios)} decisions for {tenant_id}")


def seed_checkpoint(con: sqlite3.Connection, tenant_id: str, age_hours: float = 2) -> None:
    cid = str(uuid.uuid4())
    sig = _sha256(f"sig::{tenant_id}::{cid}")
    try:
        con.execute(
            """INSERT OR IGNORE INTO audit_checkpoints
               (id, tenant_id, checkpoint_hash, signature, signer_key_id,
                prev_checkpoint_id, created_at)
               VALUES (?,?,?,?,?,NULL,?)""",
            (cid, tenant_id, _sha256(f"cp::{cid}"), sig, "demo-key-1", _ts(-age_hours)),
        )
        con.commit()
        print(f"  seeded checkpoint for {tenant_id} ({age_hours}h ago)")
    except Exception as exc:
        print(f"  checkpoint insert skipped: {exc}")


def main() -> None:
    print(f"Connecting to {DB_PATH}…")
    con = connect()
    ensure_schema(con)

    # ── Tenant: demo (healthy) ────────────────────────────────────────────
    print("\nSeeding tenant: demo (healthy)")
    seed_decisions(con, "demo", [
        {"repo": "acme/payments-api",  "status": "ALLOWED",      "pr_number": 101, "actor": "alice",   "age_offset_hours": -1},
        {"repo": "acme/payments-api",  "status": "ALLOWED",      "pr_number": 102, "actor": "bob",     "age_offset_hours": -2},
        {"repo": "acme/payments-api",  "status": "BLOCKED",      "pr_number": 103, "actor": "charlie", "age_offset_hours": -0.5},
        {"repo": "acme/auth-service",  "status": "ALLOWED",      "pr_number": 55,  "actor": "alice",   "age_offset_hours": -3},
        {"repo": "acme/auth-service",  "status": "CONDITIONAL",  "pr_number": 56,  "actor": "dave",    "age_offset_hours": -4},
        {"repo": "acme/frontend",      "status": "ALLOWED",      "pr_number": 210, "actor": "eve",     "age_offset_hours": -1.5},
        {"repo": "acme/frontend",      "status": "ALLOWED",      "pr_number": 211, "actor": "frank",   "age_offset_hours": -0.25},
        {"repo": "acme/data-pipeline", "status": "ALLOWED",      "pr_number": 77,  "actor": "alice",   "age_offset_hours": -6},
    ])
    seed_checkpoint(con, "demo", age_hours=1.5)

    # ── Tenant: demo-risk (at-risk) ───────────────────────────────────────
    print("\nSeeding tenant: demo-risk (at-risk)")
    seed_decisions(con, "demo-risk", [
        {"repo": "risky-org/core",     "status": "BLOCKED",      "pr_number": 1,  "actor": "zach",  "age_offset_hours": -0.2},
        {"repo": "risky-org/core",     "status": "BLOCKED",      "pr_number": 2,  "actor": "zach",  "age_offset_hours": -0.4},
        {"repo": "risky-org/core",     "status": "ALLOWED",      "pr_number": 3,  "actor": "quinn", "age_offset_hours": -48},
        {"repo": "risky-org/infra",    "status": "BLOCKED",      "pr_number": 10, "actor": "zach",  "age_offset_hours": -0.1},
    ])
    # Deliberately NO checkpoint for demo-risk to trigger CHECKPOINT_MISSED alert

    print("\nDemo seed complete.")
    print("  Tenants:   demo  (healthy), demo-risk (alerts firing)")
    print(f"  Dashboard: http://localhost:3000?tenant_id=demo")
    print(f"  API:       http://localhost:8000/audit/trust-status?tenant_id=demo")


if __name__ == "__main__":
    main()
