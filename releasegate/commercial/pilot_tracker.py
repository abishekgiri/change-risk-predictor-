"""Pilot Tracker — Phase 9 Commercial Proof.

Tracks design partners and paid pilots from first contact through conversion.
Captures before/after metric snapshots so the ROI story is data-driven, not
anecdotal.

Pilot statuses
--------------
PROSPECT       → identified, not yet onboarded
ONBOARDING     → setup in progress
ACTIVE         → using ReleaseGate in real workflow
CONVERTED      → paying customer
CHURNED        → ended without converting
PAUSED         → temporarily on hold

Schema (created on first use)
-----------------------------
pilots
  id              TEXT PK  (plt_YYYYMMDD_uuid8)
  tenant_id       TEXT     ReleaseGate tenant they map to (may be NULL at prospect stage)
  company_name    TEXT NOT NULL
  contact_name    TEXT
  contact_email   TEXT
  icp_band        TEXT     (STRONG / MEDIUM / WEAK)
  status          TEXT NOT NULL DEFAULT 'PROSPECT'
  pilot_start_date DATE
  pilot_end_date   DATE
  monthly_value_usd NUMERIC(10,2)
  notes           TEXT
  before_metrics  JSONB / TEXT  (snapshot at start)
  after_metrics   JSONB / TEXT  (snapshot at close / conversion)
  created_at      TIMESTAMPTZ
  updated_at      TIMESTAMPTZ
"""
from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage.db import get_db_connection

VALID_STATUSES = {
    "PROSPECT", "ONBOARDING", "ACTIVE", "CONVERTED", "CHURNED", "PAUSED",
}

ICP_BANDS = {"STRONG", "MEDIUM", "WEAK"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pilot_id() -> str:
    today = date.today().strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:8]
    return f"plt_{today}_{suffix}"


def _ensure_schema(conn) -> None:
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pilots (
            id                TEXT        NOT NULL,
            tenant_id         TEXT,
            company_name      TEXT        NOT NULL,
            contact_name      TEXT,
            contact_email     TEXT,
            icp_band          TEXT        DEFAULT 'MEDIUM',
            status            TEXT        NOT NULL DEFAULT 'PROSPECT',
            pilot_start_date  DATE,
            pilot_end_date    DATE,
            monthly_value_usd NUMERIC(10,2),
            notes             TEXT,
            before_metrics    TEXT,
            after_metrics     TEXT,
            created_at        TIMESTAMPTZ NOT NULL,
            updated_at        TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (id)
        )
    """)
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
                pass
    for key in ("pilot_start_date", "pilot_end_date", "created_at", "updated_at"):
        if d.get(key) is not None:
            d[key] = str(d[key])
    if d.get("monthly_value_usd") is not None:
        d["monthly_value_usd"] = float(d["monthly_value_usd"])
    return d


# ── CRUD ──────────────────────────────────────────────────────────────────────

def create_pilot(
    *,
    company_name: str,
    contact_name: Optional[str] = None,
    contact_email: Optional[str] = None,
    tenant_id: Optional[str] = None,
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
              (id, tenant_id, company_name, contact_name, contact_email,
               icp_band, status, pilot_start_date, pilot_end_date,
               monthly_value_usd, notes, before_metrics, after_metrics,
               created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            pilot_id, tenant_id, company_name, contact_name, contact_email,
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
    values = list(updates.values()) + [pilot_id]

    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(f"UPDATE pilots SET {set_clause} WHERE id = %s", values)
        if cur.rowcount == 0:
            raise ValueError(f"Pilot '{pilot_id}' not found")
        conn.commit()
        cur.execute("SELECT * FROM pilots WHERE id = %s", (pilot_id,))
        row = cur.fetchone()
        return _row_to_dict(row, cur)
    finally:
        conn.close()


def get_pilot(pilot_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT * FROM pilots WHERE id = %s", (pilot_id,))
        row = cur.fetchone()
        return _row_to_dict(row, cur) if row else None
    finally:
        conn.close()


def list_pilots(
    *,
    status: Optional[str] = None,
    icp_band: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        clauses, params = [], []
        if status:
            clauses.append("status = %s")
            params.append(status)
        if icp_band:
            clauses.append("icp_band = %s")
            params.append(icp_band)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        cur.execute(
            f"SELECT * FROM pilots {where} ORDER BY created_at DESC LIMIT %s",
            params + [limit],
        )
        rows = cur.fetchall()
        return [_row_to_dict(r, cur) for r in rows]
    finally:
        conn.close()


def pipeline_summary() -> Dict[str, Any]:
    """Return funnel counts and total ARR for the sales dashboard."""
    conn = get_db_connection()
    try:
        _ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("""
            SELECT
                status,
                COUNT(*)                              AS count,
                COALESCE(SUM(monthly_value_usd), 0)  AS mrr
            FROM pilots
            GROUP BY status
        """)
        by_status: Dict[str, Dict] = {}
        for row in cur.fetchall():
            by_status[row[0]] = {"count": int(row[1]), "mrr": float(row[2])}

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
