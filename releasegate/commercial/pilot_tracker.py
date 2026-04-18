"""Pilot Tracker — Phase 9 Commercial Proof.

Tracks design partners and paid pilots from first contact through conversion.

Schema (created on first use; portable across SQLite dev / Postgres prod)
------------------------------------------------------------------------
pilots
  id                TEXT PK  (plt_YYYYMMDD_uuid8)
  tenant_id         TEXT     ReleaseGate tenant they map to (NULL at prospect stage)
  owner_tenant_id   TEXT     tenant that owns the pilot record (who sees it)
  company_name      TEXT NOT NULL
  contact_name      TEXT
  contact_email     TEXT
  icp_band          TEXT
  status            TEXT NOT NULL DEFAULT 'PROSPECT'
  pilot_start_date  TEXT
  pilot_end_date    TEXT
  monthly_value_usd REAL / NUMERIC
  notes             TEXT
  before_metrics    TEXT
  after_metrics     TEXT
  created_at        TEXT (ISO-8601)
  updated_at        TEXT (ISO-8601)
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage.db import get_db_connection

log = logging.getLogger(__name__)

VALID_STATUSES = {
    "PROSPECT", "ONBOARDING", "ACTIVE", "CONVERTED", "CHURNED", "PAUSED",
}

ICP_BANDS = {"STRONG", "MEDIUM", "WEAK"}

# Used when no owner tenant is supplied. Back-compat for older records.
_DEFAULT_OWNER_TENANT = "default"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pilot_id() -> str:
    today = date.today().strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:8]
    return f"plt_{today}_{suffix}"


def _money_type(dialect: str) -> str:
    return "NUMERIC(10,2)" if dialect == "postgres" else "REAL"


def _ensure_schema(conn) -> None:
    """Create pilots table if missing and backfill owner_tenant_id column.

    Schema-on-use is intentional here — pilot tracking is a commercial
    module layered on top of core governance, and this lets it run on a
    fresh dev DB without a separate migration step. If a migration
    framework is adopted later, lift this into the migrations folder.
    """
    dialect = getattr(conn, "dialect", "sqlite")
    money = _money_type(dialect)
    cur = conn.cursor()
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS pilots (
            id                TEXT        NOT NULL,
            tenant_id         TEXT,
            owner_tenant_id   TEXT        NOT NULL DEFAULT '{_DEFAULT_OWNER_TENANT}',
            company_name      TEXT        NOT NULL,
            contact_name      TEXT,
            contact_email     TEXT,
            icp_band          TEXT        DEFAULT 'MEDIUM',
            status            TEXT        NOT NULL DEFAULT 'PROSPECT',
            pilot_start_date  TEXT,
            pilot_end_date    TEXT,
            monthly_value_usd {money},
            notes             TEXT,
            before_metrics    TEXT,
            after_metrics     TEXT,
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL,
            PRIMARY KEY (id)
        )
    """)
    # Back-compat: older deployments created this table without owner_tenant_id.
    # Add it if missing. (ALTER TABLE ... ADD COLUMN IF NOT EXISTS is Postgres-9.6+;
    # SQLite has no IF NOT EXISTS on ADD COLUMN, so we probe first.)
    try:
        if dialect == "postgres":
            cur.execute(
                "ALTER TABLE pilots ADD COLUMN IF NOT EXISTS owner_tenant_id "
                f"TEXT NOT NULL DEFAULT '{_DEFAULT_OWNER_TENANT}'"
            )
        else:
            cur.execute("PRAGMA table_info(pilots)")
            cols = {row[1] for row in cur.fetchall()}
            if "owner_tenant_id" not in cols:
                cur.execute(
                    "ALTER TABLE pilots ADD COLUMN owner_tenant_id TEXT "
                    f"NOT NULL DEFAULT '{_DEFAULT_OWNER_TENANT}'"
                )
    except Exception:
        # If the ALTER fails (e.g. permissions) we'll surface later on INSERT.
        try:
            conn.rollback()
        except Exception:
            pass
    conn.commit()


def _row_to_dict(row, cursor) -> Dict[str, Any]:
    cols = [d[0] for d in cursor.description]
    d = dict(zip(cols, row))
    for key in ("before_metrics", "after_metrics"):
        val = d.get(key)
        if val and isinstance(val, str):
            try:
                d[key] = json.loads(val)
            except Exception:
                # Corrupt JSON: drop it and log, rather than silently returning
                # a raw string that downstream consumers will mishandle.
                log.warning(
                    "pilot_tracker: dropping corrupt JSON in column %s (pilot id=%s)",
                    key, d.get("id"),
                )
                d[key] = None
    for key in ("pilot_start_date", "pilot_end_date", "created_at", "updated_at"):
        if d.get(key) is not None:
            d[key] = str(d[key])
    if d.get("monthly_value_usd") is not None:
        try:
            d["monthly_value_usd"] = float(d["monthly_value_usd"])
        except (TypeError, ValueError):
            d["monthly_value_usd"] = None
    return d


# ── CRUD ──────────────────────────────────────────────────────────────────────

def create_pilot(
    *,
    company_name: str,
    contact_name: Optional[str] = None,
    contact_email: Optional[str] = None,
    tenant_id: Optional[str] = None,
    owner_tenant_id: str = _DEFAULT_OWNER_TENANT,
    icp_band: str = "MEDIUM",
    status: str = "PROSPECT",
    pilot_start_date: Optional[str] = None,
    pilot_end_date: Optional[str] = None,
    monthly_value_usd: Optional[float] = None,
    notes: Optional[str] = None,
    before_metrics: Optional[Dict] = None,
) -> Dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Valid: {sorted(VALID_STATUSES)}")
    if icp_band not in ICP_BANDS:
        raise ValueError(f"Invalid icp_band '{icp_band}'. Valid: {sorted(ICP_BANDS)}")

    pilot_id = _pilot_id()
    now = _now_iso()

    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO pilots
              (id, tenant_id, owner_tenant_id, company_name, contact_name, contact_email,
               icp_band, status, pilot_start_date, pilot_end_date,
               monthly_value_usd, notes, before_metrics, after_metrics,
               created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            pilot_id, tenant_id, owner_tenant_id, company_name, contact_name, contact_email,
            icp_band, status, pilot_start_date, pilot_end_date,
            monthly_value_usd, notes,
            json.dumps(before_metrics) if before_metrics else None,
            None,
            now, now,
        ))
        conn.commit()
        cur.execute("SELECT * FROM pilots WHERE id = %s", (pilot_id,))
        row = cur.fetchone()
        return _row_to_dict(row, cur)
    finally:
        conn.close()


def update_pilot(
    pilot_id: str,
    *,
    owner_tenant_id: str = _DEFAULT_OWNER_TENANT,
    status: Optional[str] = None,
    notes: Optional[str] = None,
    tenant_id: Optional[str] = None,
    icp_band: Optional[str] = None,
    pilot_start_date: Optional[str] = None,
    pilot_end_date: Optional[str] = None,
    monthly_value_usd: Optional[float] = None,
    before_metrics: Optional[Dict] = None,
    after_metrics: Optional[Dict] = None,
    contact_name: Optional[str] = None,
    contact_email: Optional[str] = None,
) -> Dict[str, Any]:
    if status and status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'")

    updates: Dict[str, Any] = {"updated_at": _now_iso()}
    if status            is not None: updates["status"]             = status
    if notes             is not None: updates["notes"]              = notes
    if tenant_id         is not None: updates["tenant_id"]          = tenant_id
    if icp_band          is not None: updates["icp_band"]           = icp_band
    if pilot_start_date  is not None: updates["pilot_start_date"]   = pilot_start_date
    if pilot_end_date    is not None: updates["pilot_end_date"]     = pilot_end_date
    if monthly_value_usd is not None: updates["monthly_value_usd"]  = monthly_value_usd
    if contact_name      is not None: updates["contact_name"]       = contact_name
    if contact_email     is not None: updates["contact_email"]      = contact_email
    if before_metrics    is not None: updates["before_metrics"]     = json.dumps(before_metrics)
    if after_metrics     is not None: updates["after_metrics"]      = json.dumps(after_metrics)

    set_clause = ", ".join(f"{k} = %s" for k in updates)
    values = list(updates.values()) + [pilot_id, owner_tenant_id]

    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(
            f"UPDATE pilots SET {set_clause} WHERE id = %s AND owner_tenant_id = %s",
            values,
        )
        if cur.rowcount == 0:
            raise ValueError(f"Pilot '{pilot_id}' not found")
        conn.commit()
        cur.execute(
            "SELECT * FROM pilots WHERE id = %s AND owner_tenant_id = %s",
            (pilot_id, owner_tenant_id),
        )
        row = cur.fetchone()
        return _row_to_dict(row, cur)
    finally:
        conn.close()


def get_pilot(
    pilot_id: str,
    *,
    owner_tenant_id: str = _DEFAULT_OWNER_TENANT,
) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM pilots WHERE id = %s AND owner_tenant_id = %s",
            (pilot_id, owner_tenant_id),
        )
        row = cur.fetchone()
        return _row_to_dict(row, cur) if row else None
    finally:
        conn.close()


def list_pilots(
    *,
    owner_tenant_id: str = _DEFAULT_OWNER_TENANT,
    status: Optional[str] = None,
    icp_band: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        clauses: List[str] = ["owner_tenant_id = %s"]
        params: List[Any] = [owner_tenant_id]
        if status:
            clauses.append("status = %s")
            params.append(status)
        if icp_band:
            clauses.append("icp_band = %s")
            params.append(icp_band)
        where = "WHERE " + " AND ".join(clauses)
        cur.execute(
            f"SELECT * FROM pilots {where} ORDER BY created_at DESC LIMIT %s",
            params + [limit],
        )
        rows = cur.fetchall()
        return [_row_to_dict(r, cur) for r in rows]
    finally:
        conn.close()


def pipeline_summary(
    *,
    owner_tenant_id: str = _DEFAULT_OWNER_TENANT,
) -> Dict[str, Any]:
    """Return funnel counts and total ARR for the sales dashboard."""
    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                status,
                COUNT(*)                              AS count,
                COALESCE(SUM(monthly_value_usd), 0)  AS mrr
            FROM pilots
            WHERE owner_tenant_id = %s
            GROUP BY status
            """,
            (owner_tenant_id,),
        )
        by_status: Dict[str, Dict] = {}
        for row in cur.fetchall():
            by_status[row[0]] = {"count": int(row[1]), "mrr": float(row[2] or 0)}

        total_mrr = sum(
            v["mrr"] for k, v in by_status.items()
            if k in ("ACTIVE", "CONVERTED")
        )
        converted = by_status.get("CONVERTED", {}).get("count", 0)
        active    = by_status.get("ACTIVE",    {}).get("count", 0)
        prospects = by_status.get("PROSPECT",  {}).get("count", 0)

        return {
            "by_status": by_status,
            "total_active_mrr": round(total_mrr, 2),
            "total_arr": round(total_mrr * 12, 2),
            "converted_count": converted,
            "active_pilots": active,
            "prospects": prospects,
        }
    finally:
        conn.close()
