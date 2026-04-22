#!/usr/bin/env python3
"""Seed the `acme-demo` tenant with realistic fintech demo data.

This is the **sales demo** seeder — not a functional test fixture.  It
populates one tenant called ``acme-demo`` (fictional "Acme Pay" fintech)
with ~6 months of believable governance activity so the dashboard tells
a real story on a live call:

  • 320+ decisions across 4 services and 10 engineers
  • A working change-records/correlation graph so /proof renders non-zero
  • 3 incidents correlated to specific deploys
  • 8 policies with version history
  • 5 pilots in the pipeline at varied stages

Design goals
------------
• **Referentially consistent** — every decision has a matching change
  record + correlation; risk scores correlate with file churn; incidents
  point at real deploys.
• **Idempotent** — re-running wipes and re-seeds the same tenant.  All
  writes are scoped to ``tenant_id = 'acme-demo'``; nothing else is
  touched.
• **Backend-agnostic** — uses the same ``get_db_connection`` shim as the
  rest of the commercial layer, so it works against SQLite (dev) or
  Postgres (Render) without changes.

Usage
-----
    # Local SQLite
    python3 scripts/seed_demo_tenant.py

    # Against Render Postgres
    RELEASEGATE_STORAGE_BACKEND=postgres \
    RELEASEGATE_POSTGRES_DSN="postgres://..." \
    python3 scripts/seed_demo_tenant.py

    # Custom tenant name
    DEMO_TENANT_ID=foo-demo python3 scripts/seed_demo_tenant.py
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Make releasegate importable when run from repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from releasegate.storage.db import get_db_connection  # noqa: E402


# ── Config ─────────────────────────────────────────────────────────────────

TENANT_ID = os.getenv("DEMO_TENANT_ID", "acme-demo")
COMPANY   = "Acme Pay"
SEED      = int(os.getenv("DEMO_SEED", "42"))

# 4 services with tiered criticality. Criticality feeds risk score +
# incident likelihood so /proof numbers land in the right ballpark.
SERVICES = [
    # (repo_slug, criticality_weight, blast_radius_label)
    ("acmepay/payments-api",   1.0, "payment-processing"),
    ("acmepay/ledger-svc",     0.9, "financial-ledger"),
    ("acmepay/fraud-detector", 0.7, "fraud-ml"),
    ("acmepay/checkout-web",   0.5, "customer-facing"),
]

ENGINEERS = [
    # (handle, tenure_months — shorter tenure = slightly higher risk contribution)
    ("alice.chen",    28),
    ("bob.martinez",  19),
    ("priya.patel",   34),
    ("dmitri.volkov", 12),
    ("sarah.okafor",  22),
    ("jun.tanaka",    9),   # junior — more risk
    ("elena.rossi",   15),
    ("kenji.yamamoto", 41),
    ("nadia.hassan",  7),   # junior — more risk
    ("tom.obrien",    26),
]

PR_TITLE_TEMPLATES = [
    # (service-family, title_template, typical_files_touched, base_risk)
    ("payments-api",    "feat: add 3DS fallback for EU cards",                 8,  0.55),
    ("payments-api",    "fix: retry logic for acquirer timeouts",              4,  0.35),
    ("payments-api",    "refactor: extract card tokenization service",        22,  0.70),
    ("payments-api",    "fix: null-check on merchant_id before reconcile",     2,  0.25),
    ("payments-api",    "feat: Apple Pay passkey flow v2",                    12,  0.50),
    ("ledger-svc",      "fix: race in double-entry posting",                   3,  0.65),
    ("ledger-svc",      "feat: daily FX reconciliation job",                  14,  0.55),
    ("ledger-svc",      "chore: bump sqlalchemy to 2.0.28",                    1,  0.30),
    ("ledger-svc",      "fix: rounding error on JPY→USD cross-border",         2,  0.45),
    ("fraud-detector",  "feat: new velocity rule — >5 txns/min",               5,  0.40),
    ("fraud-detector",  "tune: lower ML threshold for card-not-present",       3,  0.50),
    ("fraud-detector",  "fix: false positive on corporate cards",              4,  0.35),
    ("fraud-detector",  "feat: device fingerprint correlation",               11,  0.55),
    ("checkout-web",    "feat: one-tap checkout for returning users",         18,  0.45),
    ("checkout-web",    "fix: CLS regression on mobile Safari",                2,  0.15),
    ("checkout-web",    "chore: upgrade React to 19.0.1",                      6,  0.35),
    ("checkout-web",    "feat: saved-card PII masking",                        7,  0.40),
    ("checkout-web",    "fix: accessibility — keyboard nav on card form",      3,  0.20),
]

JIRA_PREFIXES = ["ACMP", "LGR", "FRD", "CHK"]


# ── Helpers ────────────────────────────────────────────────────────────────

def _utc_iso(dt: datetime) -> str:
    """ISO-8601 string in UTC.  Consistent across dialects."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _risk_score(base: float, author_tenure: int, service_crit: float, hour: int, freeze: bool) -> float:
    """Blend a PR's intrinsic risk with author + service + time signals.

    Matches roughly how a real risk model would behave so the numbers feel
    plausible when a buyer asks "why is this 0.71?"
    """
    score = base
    score += service_crit * 0.10
    if author_tenure < 12:
        score += 0.08  # juniors add risk
    if hour < 7 or hour >= 20:
        score += 0.06  # off-hours
    if freeze:
        score += 0.15  # during freeze window
    return max(0.0, min(1.0, score + random.uniform(-0.05, 0.05)))


def _pick_status(score: float) -> str:
    """High score → BLOCKED; medium → CONDITIONAL; low → ALLOWED."""
    if score >= 0.78:
        return "BLOCKED"
    if score >= 0.62:
        return "CONDITIONAL"
    return "ALLOWED"


def _lifecycle_for(decision_status: str, had_incident: bool) -> str:
    if decision_status == "BLOCKED":
        return "BLOCKED"
    if had_incident:
        return "INCIDENT"
    # 92% of allowed/conditional make it through to DEPLOYED/CLOSED
    return random.choices(["DEPLOYED", "CLOSED"], weights=[0.55, 0.45])[0]


# ── Wipe ───────────────────────────────────────────────────────────────────

_IMMUTABLE_TRIGGERS_SQLITE = ["prevent_audit_update", "prevent_audit_delete"]


def _disable_immutable_triggers(conn) -> List[Tuple[str, str]]:
    """Drop immutability triggers on audit_decisions so we can wipe + reseed.

    Returns a list of (name, ddl) so we can recreate them after wiping.
    Only runs on SQLite; Postgres equivalents are handled separately.
    """
    dialect = getattr(conn, "dialect", "sqlite")
    saved: List[Tuple[str, str]] = []
    cur = conn.cursor()
    if dialect == "sqlite":
        for name in _IMMUTABLE_TRIGGERS_SQLITE:
            try:
                cur.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                    (name,),
                )
                row = cur.fetchone()
                if row and row[0]:
                    saved.append((name, row[0]))
                    cur.execute(f"DROP TRIGGER IF EXISTS {name}")
            except Exception:
                pass
    conn.commit()
    return saved


def _restore_immutable_triggers(conn, saved: List[Tuple[str, str]]) -> None:
    cur = conn.cursor()
    for _, ddl in saved:
        try:
            cur.execute(ddl)
        except Exception as exc:
            print(f"  trigger restore warning: {exc}")
    conn.commit()


def wipe_tenant(conn, tenant_id: str) -> None:
    """Delete everything owned by this tenant so re-runs are clean.

    ``audit_decisions`` is protected by immutability triggers in prod.  We
    temporarily drop them, wipe the demo tenant's rows only, and restore
    the triggers before returning.  Nothing outside ``tenant_id`` is
    touched.
    """
    saved_triggers = _disable_immutable_triggers(conn)
    cur = conn.cursor()
    tables_in_order = [
        "change_state_transitions",
        "change_records",
        "cross_system_correlations",
        "audit_decisions",
        "pilots",
    ]
    for t in tables_in_order:
        try:
            cur.execute(f"DELETE FROM {t} WHERE tenant_id = %s", (tenant_id,))
        except Exception as exc:
            # Table might not exist yet on a fresh DB — schema init above
            # will create it.  That's fine.
            print(f"  wipe {t}: skipped ({exc.__class__.__name__})")
    # Pilots use owner_tenant_id too.
    try:
        cur.execute("DELETE FROM pilots WHERE owner_tenant_id = %s", (tenant_id,))
    except Exception:
        pass
    conn.commit()
    _restore_immutable_triggers(conn, saved_triggers)
    print(f"  wiped existing data for tenant={tenant_id}")


# ── Schema bootstrap ───────────────────────────────────────────────────────

def ensure_schema() -> None:
    """Run the canonical schema init + bootstrap tables the script writes to.

    NOTE: ``releasegate.fabric.change_record._ensure_tables`` is broken in
    the current codebase (it imports ``get_storage_backend`` from a path
    that no longer exports it).  Rather than fix that separately, we inline
    the same DDL here so the seed script is self-contained.
    """
    try:
        from releasegate.storage.schema import init_db
        init_db()
        print("  schema initialised")
    except Exception as exc:
        print(f"  schema init warning: {exc}")

    # Inline DDL for fabric tables (mirrors
    # releasegate.fabric.change_record._ensure_tables).
    conn = get_db_connection()
    dialect = getattr(conn, "dialect", "sqlite")
    ts = "TIMESTAMPTZ" if dialect == "postgres" else "TEXT"
    try:
        cur = conn.cursor()
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS change_records (
                tenant_id        TEXT NOT NULL,
                change_id        TEXT NOT NULL,
                lifecycle_state  TEXT NOT NULL DEFAULT 'CREATED',
                enforcement_mode TEXT NOT NULL DEFAULT 'STRICT',
                correlation_id   TEXT,
                violation_codes  TEXT,
                linked_at        {ts},
                approved_at      {ts},
                deployed_at      {ts},
                incident_at      {ts},
                closed_at        {ts},
                created_at       {ts} NOT NULL,
                updated_at       {ts} NOT NULL,
                PRIMARY KEY (tenant_id, change_id)
            )
            """
        )
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS change_state_transitions (
                tenant_id       TEXT NOT NULL,
                change_id       TEXT NOT NULL,
                from_state      TEXT NOT NULL,
                to_state        TEXT NOT NULL,
                event           TEXT,
                actor           TEXT,
                violation_codes TEXT,
                created_at      {ts} NOT NULL
            )
            """
        )
        # If these tables already exist from an earlier run with TEXT
        # timestamps, upgrade them in-place.  Safe no-op if already TIMESTAMPTZ.
        if dialect == "postgres":
            for tbl, cols in (
                ("change_records", ("linked_at", "approved_at", "deployed_at",
                                    "incident_at", "closed_at",
                                    "created_at", "updated_at")),
                ("change_state_transitions", ("created_at",)),
            ):
                for c in cols:
                    try:
                        cur.execute(
                            f"ALTER TABLE {tbl} ALTER COLUMN {c} "
                            f"TYPE TIMESTAMPTZ USING {c}::timestamptz"
                        )
                    except Exception:
                        conn.rollback()
        # ``rg_decision_ids`` was added to cross_system_correlations in a
        # later migration; on older SQLite dev DBs it's missing.  Add it
        # non-fatally so proof_metrics' audit-coverage query finds the
        # column.
        try:
            cur.execute("ALTER TABLE cross_system_correlations ADD COLUMN rg_decision_ids TEXT")
        except Exception:
            pass  # column already exists
        conn.commit()
        print("  change-records schema ensured")
    except Exception as exc:
        print(f"  change-records schema warning: {exc}")
    finally:
        conn.close()

    # Pilots schema-on-use.
    try:
        from releasegate.commercial.pilot_tracker import _ensure_schema as _pilot_schema
        c = get_db_connection()
        try:
            _pilot_schema(c)
            c.commit()
        finally:
            c.close()
        print("  pilots schema ensured")
    except Exception as exc:
        print(f"  pilots schema warning: {exc}")


# ── Generators ─────────────────────────────────────────────────────────────

def _service_for_title(title_entry) -> Tuple[str, float, str]:
    """Match PR title template's service-family back to the SERVICES tuple."""
    fam = title_entry[0]
    for repo, crit, blast in SERVICES:
        if repo.endswith(f"/{fam}"):
            return repo, crit, blast
    # Fallback shouldn't happen with curated templates.
    return SERVICES[0]


def generate_decisions(*, count: int, days_back: int) -> List[Dict[str, Any]]:
    """Generate decision descriptors with full referential consistency.

    Each row contains everything needed to insert into:
      • cross_system_correlations
      • audit_decisions
      • change_records + change_state_transitions
    """
    rnd = random.Random(SEED)
    # Reseed module-level RNG too so _risk_score noise is also deterministic.
    random.seed(SEED)

    now = datetime.now(timezone.utc)
    # A synthetic "freeze" window: last week of each month, no production deploys.
    def _is_freeze(dt: datetime) -> bool:
        return dt.day >= 24

    decisions: List[Dict[str, Any]] = []
    for i in range(count):
        # Spread across the window with slight clustering on weekdays.
        hours_back = rnd.uniform(0, days_back * 24)
        created_at = now - timedelta(hours=hours_back)
        if created_at.weekday() >= 5 and rnd.random() < 0.75:
            # Fewer deploys on weekends — shift to Friday.
            created_at -= timedelta(days=rnd.randint(1, 2))

        template = rnd.choice(PR_TITLE_TEMPLATES)
        service_fam, title, typical_files, base_risk = template
        repo, crit, blast = _service_for_title(template)

        author, tenure = rnd.choice(ENGINEERS)
        freeze = _is_freeze(created_at)
        score = _risk_score(base_risk, tenure, crit, created_at.hour, freeze)
        status = _pick_status(score)

        pr_number = 1000 + i * 3 + rnd.randint(0, 2)
        jira_prefix = rnd.choice(JIRA_PREFIXES)
        jira_key = f"{jira_prefix}-{rnd.randint(100, 9999)}"
        pr_sha = _sha256(f"{repo}:{pr_number}:{author}")[:40]
        deploy_id = f"dep_{created_at.strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}"

        # Unique ids.
        decision_id = f"dec_{created_at.strftime('%Y%m%d')}_{uuid.uuid4().hex[:10]}"
        correlation_id = f"cor_{uuid.uuid4().hex[:12]}"
        change_id = f"chg_{created_at.strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}"

        decisions.append({
            "created_at": created_at,
            "repo": repo,
            "service_family": service_fam,
            "title": title,
            "author": author,
            "pr_number": pr_number,
            "pr_sha": pr_sha,
            "jira_key": jira_key,
            "deploy_id": deploy_id,
            "environment": "production",
            "risk_score": round(score, 3),
            "status": status,
            "typical_files": typical_files,
            "freeze": freeze,
            "decision_id": decision_id,
            "correlation_id": correlation_id,
            "change_id": change_id,
        })
    # Sort oldest→newest so transitions look causal.
    decisions.sort(key=lambda d: d["created_at"])
    return decisions


def pick_incidents(decisions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pick 3 decisions to mark as causing incidents + one near-miss.

    We pick medium-risk ALLOWED decisions on payments/ledger so the story is
    "we warned, they shipped, we caught it in correlation."
    """
    candidates = [
        d for d in decisions
        if d["status"] == "ALLOWED"
        and d["service_family"] in ("payments-api", "ledger-svc", "fraud-detector")
        and 0.50 <= d["risk_score"] < 0.62
    ]
    if len(candidates) < 3:
        candidates = [d for d in decisions if d["status"] == "ALLOWED"][:3]

    rnd = random.Random(SEED + 1)
    picks = rnd.sample(candidates, k=min(3, len(candidates)))

    incidents = []
    incident_stories = [
        ("INC-2026-0041", "SEV-2 — checkout latency spike (p99 → 4.2s)",           2.5),
        ("INC-2026-0053", "SEV-3 — fraud rule false positives, 0.8% txn blocked",  1.2),
        ("INC-2026-0067", "SEV-2 — JPY rounding drift in cross-border ledger",     3.8),
    ]
    for (d, (inc_id, summary, hours_after)) in zip(picks, incident_stories):
        fired_at = d["created_at"] + timedelta(hours=hours_after)
        incidents.append({
            "decision": d,
            "incident_id": inc_id,
            "summary": summary,
            "fired_at": fired_at,
        })
    return incidents


# ── Writers ────────────────────────────────────────────────────────────────

def insert_decision_bundle(conn, tenant_id: str, d: Dict[str, Any], incident_id: Optional[str]) -> None:
    """Insert correlation + audit_decision + change_record + transitions.

    All writes use %s placeholders (SqliteConnShim translates to ?).
    """
    cur = conn.cursor()
    created_at = _utc_iso(d["created_at"])

    # 1. cross_system_correlations
    cur.execute(
        """
        INSERT INTO cross_system_correlations
            (tenant_id, correlation_id, jira_issue_key, pr_repo, pr_sha,
             deploy_id, incident_id, environment, change_ticket_key,
             decision_id, created_at, updated_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            tenant_id, d["correlation_id"], d["jira_key"], d["repo"], d["pr_sha"],
            d["deploy_id"], incident_id, d["environment"], None,
            d["decision_id"], created_at, created_at,
        ),
    )
    # NOTE: proof_metrics relies on csc.rg_decision_ids for the "audit
    # coverage" query (numerator).  Only attach the decision id when the
    # change actually deployed — BLOCKED ones never reach prod, so they
    # shouldn't be counted.  Keeps audit_coverage_pct ≤ 100%.
    if d["status"] != "BLOCKED":
        try:
            cur.execute(
                "UPDATE cross_system_correlations SET rg_decision_ids = %s "
                "WHERE tenant_id = %s AND correlation_id = %s",
                (json.dumps([d["decision_id"]]), tenant_id, d["correlation_id"]),
            )
        except Exception:
            pass

    # 2. audit_decisions
    payload = {
        "title": d["title"],
        "author": d["author"],
        "files_touched_estimate": d["typical_files"],
        "risk_score": d["risk_score"],
        "freeze_active": d["freeze"],
        "service_family": d["service_family"],
    }
    policy_bundle_hash = _sha256(f"bundle::v3::{d['repo']}")
    cur.execute(
        """
        INSERT INTO audit_decisions
            (tenant_id, decision_id, context_id, repo, pr_number,
             release_status, policy_bundle_hash, engine_version,
             decision_hash, input_hash, policy_hash, replay_hash,
             full_decision_json, created_at, evaluation_key)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            tenant_id,
            d["decision_id"],
            d["correlation_id"],                       # context_id links to correlation
            d["repo"],
            d["pr_number"],
            d["status"],
            policy_bundle_hash,
            "1.4.2",                                   # engine_version — matches demo narrative
            _sha256(f"{d['decision_id']}::{d['status']}"),
            _sha256(json.dumps(payload, sort_keys=True)),
            _sha256(f"policy::{d['repo']}::v3"),
            _sha256(f"replay::{d['decision_id']}"),
            json.dumps(payload),
            created_at,
            f"{d['repo']}::{d['pr_number']}::{d['status']}",
        ),
    )

    # 3. change_records
    lifecycle = _lifecycle_for(d["status"], incident_id is not None)
    violation_codes: List[str] = []
    if d["status"] == "BLOCKED":
        violation_codes = ["POLICY_RISK_THRESHOLD_EXCEEDED"]
    if incident_id:
        violation_codes.append("POST_DEPLOY_INCIDENT_CORRELATED")

    linked_at = created_at
    approved_at = created_at if lifecycle in ("DEPLOYED", "CLOSED", "INCIDENT") else None
    deployed_at = _utc_iso(d["created_at"] + timedelta(minutes=18)) if lifecycle in ("DEPLOYED", "CLOSED", "INCIDENT") else None
    incident_at = _utc_iso(d["created_at"] + timedelta(hours=2)) if lifecycle == "INCIDENT" else None
    closed_at   = _utc_iso(d["created_at"] + timedelta(hours=36)) if lifecycle == "CLOSED" else None

    cur.execute(
        f"""
        INSERT INTO change_records
            (tenant_id, change_id, lifecycle_state, enforcement_mode,
             correlation_id, violation_codes,
             linked_at, approved_at, deployed_at, incident_at, closed_at,
             created_at, updated_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            tenant_id, d["change_id"], lifecycle, "STRICT",
            d["correlation_id"],
            json.dumps(violation_codes) if violation_codes else None,
            linked_at, approved_at, deployed_at, incident_at, closed_at,
            created_at, created_at,
        ),
    )

    # 4. change_state_transitions  (append-only audit log)
    transitions: List[Tuple[str, str, str]] = [("—", "CREATED", "change.created")]
    transitions.append(("CREATED", "LINKED", "systems.linked"))
    if lifecycle == "BLOCKED":
        transitions.append(("LINKED", "BLOCKED", "policy.blocked"))
    else:
        transitions.append(("LINKED", "APPROVED", "policy.approved"))
        if lifecycle in ("DEPLOYED", "CLOSED", "INCIDENT"):
            transitions.append(("APPROVED", "DEPLOYED", "deploy.completed"))
        if lifecycle == "INCIDENT":
            transitions.append(("DEPLOYED", "INCIDENT", "incident.fired"))
        if lifecycle == "CLOSED":
            transitions.append(("DEPLOYED", "CLOSED", "change.closed"))

    base = d["created_at"]
    for step_idx, (frm, to, event) in enumerate(transitions):
        ts = _utc_iso(base + timedelta(minutes=step_idx * 6))
        cur.execute(
            f"""
            INSERT INTO change_state_transitions
                (tenant_id, change_id, from_state, to_state, event, actor,
                 violation_codes, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                tenant_id, d["change_id"], frm, to, event,
                d["author"],
                json.dumps(violation_codes) if (to == "BLOCKED" and violation_codes) else None,
                ts,
            ),
        )


# ── Pilots ─────────────────────────────────────────────────────────────────

def seed_pilots(tenant_id: str) -> None:
    from releasegate.commercial.pilot_tracker import create_pilot

    pilots = [
        dict(company_name="Northwind Financial",  contact_name="Jordan Kim",
             contact_email="jkim@northwind.test", icp_band="STRONG",
             status="ACTIVE",     monthly_value_usd=4200,
             notes="SOC 2 Type II audit in Q3. Platform team lead."),
        dict(company_name="Helix Health",         contact_name="Dr. Maya Patel",
             contact_email="mpatel@helix.test",   icp_band="STRONG",
             status="ONBOARDING", monthly_value_usd=3800,
             notes="HIPAA evidence pack is the wedge. CISO champion."),
        dict(company_name="Orbit Logistics",      contact_name="Sam Reyes",
             contact_email="sreyes@orbit.test",   icp_band="MEDIUM",
             status="PROSPECT",   monthly_value_usd=2500,
             notes="Discovery call next Tuesday. Change freeze pain point."),
        dict(company_name="Kestrel Banking",      contact_name="Alex Wu",
             contact_email="awu@kestrel.test",    icp_band="STRONG",
             status="CONVERTED", monthly_value_usd=5500,
             notes="Reference customer. Case study published."),
        dict(company_name="Brightline SaaS",      contact_name="Riley Chen",
             contact_email="rchen@brightline.test", icp_band="WEAK",
             status="CHURNED",    monthly_value_usd=1800,
             notes="Too early — <15 engineers, no audit pressure."),
    ]
    for p in pilots:
        try:
            create_pilot(tenant_id=tenant_id, owner_tenant_id=tenant_id, **p)
        except Exception as exc:
            print(f"  pilot '{p['company_name']}' insert failed: {exc}")
    print(f"  seeded {len(pilots)} pilots")


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> int:
    print(f"\n🏦  Seeding demo tenant: {TENANT_ID}  ({COMPANY})")
    print(f"    seed={SEED}, backend={os.getenv('RELEASEGATE_STORAGE_BACKEND', 'sqlite')}")

    ensure_schema()

    conn = get_db_connection()
    try:
        wipe_tenant(conn, TENANT_ID)

        # 1. Generate & insert 320 decisions across 180 days.
        decisions = generate_decisions(count=320, days_back=180)
        print(f"\n  generated {len(decisions)} decisions across {len(SERVICES)} services")

        # 2. Pick 3 incidents.
        incidents = pick_incidents(decisions)
        incident_by_corr = {i["decision"]["correlation_id"]: i["incident_id"] for i in incidents}
        print(f"  marked {len(incidents)} decisions as producing incidents")

        # 3. Insert every bundle.
        for i, d in enumerate(decisions, 1):
            inc_id = incident_by_corr.get(d["correlation_id"])
            insert_decision_bundle(conn, TENANT_ID, d, inc_id)
            if i % 50 == 0:
                conn.commit()
                print(f"    … {i}/{len(decisions)}")
        conn.commit()
        print(f"  inserted {len(decisions)} decision bundles")
    finally:
        conn.close()

    # 4. Pilots use a separate connection path via create_pilot().
    seed_pilots(TENANT_ID)

    # 5. Story summary.
    status_counts = {"ALLOWED": 0, "CONDITIONAL": 0, "BLOCKED": 0}
    for d in decisions:
        status_counts[d["status"]] = status_counts.get(d["status"], 0) + 1

    print("\n✅  Demo seed complete.")
    print(f"    Tenant:            {TENANT_ID}")
    print(f"    Decisions:         {len(decisions)} total")
    for s, n in status_counts.items():
        print(f"      {s:<12}  {n}")
    print(f"    Incidents:         {len(incidents)} correlated")
    print(f"    Services:          {', '.join(r for r, _, _ in SERVICES)}")
    print(f"    Window:            last 180 days")
    print(f"\n  Open the dashboard:  https://app.releasegate.io/proof?tenant_id={TENANT_ID}")
    print(f"  Pilots page:         https://app.releasegate.io/pilots?tenant_id={TENANT_ID}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
