from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


STATUS_PENDING = "PENDING"
STATUS_SUBMITTED = "SUBMITTED"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_FAILED = "FAILED"

RETRYABLE_STATUSES = (STATUS_PENDING, STATUS_FAILED)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _normalize_status(value: Any) -> str:
    raw = str(value or "").strip().upper()
    if raw in {STATUS_PENDING, STATUS_SUBMITTED, STATUS_CONFIRMED, STATUS_FAILED}:
        return raw
    return STATUS_PENDING


def _row_to_job(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tenant_id": row.get("tenant_id"),
        "job_id": row.get("job_id"),
        "root_hash": row.get("root_hash"),
        "date_utc": row.get("date_utc"),
        "ledger_head_seq": _to_int(row.get("ledger_head_seq"), 0),
        "status": _normalize_status(row.get("status")),
        "attempts": _to_int(row.get("attempts"), 0),
        "next_attempt_at": row.get("next_attempt_at"),
        "last_error": row.get("last_error"),
        "external_anchor_id": row.get("external_anchor_id"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "submitted_at": row.get("submitted_at"),
        "confirmed_at": row.get("confirmed_at"),
    }


def ensure_anchor_jobs_table() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS anchor_jobs (
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            root_hash TEXT NOT NULL,
            date_utc TEXT NOT NULL,
            ledger_head_seq INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT NOT NULL,
            last_error TEXT,
            external_anchor_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            submitted_at TEXT,
            confirmed_at TEXT,
            PRIMARY KEY (tenant_id, job_id)
        )
        """
    )
    storage.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_anchor_jobs_tenant_root_hash
        ON anchor_jobs(tenant_id, root_hash)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_anchor_jobs_tenant_status_next_attempt
        ON anchor_jobs(tenant_id, status, next_attempt_at)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_anchor_jobs_status_next_attempt
        ON anchor_jobs(status, next_attempt_at)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_anchor_jobs_tenant_created_at
        ON anchor_jobs(tenant_id, created_at DESC)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_anchor_jobs_tenant_confirmed_at
        ON anchor_jobs(tenant_id, confirmed_at DESC)
        """
    )


def _get_job_by_root(*, tenant_id: str, root_hash: str) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
               next_attempt_at, last_error, external_anchor_id, created_at, updated_at,
               submitted_at, confirmed_at
        FROM anchor_jobs
        WHERE tenant_id = ? AND root_hash = ?
        LIMIT 1
        """,
        (tenant_id, root_hash),
    )
    if not row:
        return None
    return _row_to_job(row)


def get_anchor_job(*, tenant_id: Optional[str], job_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
               next_attempt_at, last_error, external_anchor_id, created_at, updated_at,
               submitted_at, confirmed_at
        FROM anchor_jobs
        WHERE tenant_id = ? AND job_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(job_id)),
    )
    if not row:
        return None
    return _row_to_job(row)


def upsert_anchor_job(
    *,
    tenant_id: Optional[str],
    root_hash: str,
    date_utc: str,
    ledger_head_seq: int,
    next_attempt_at: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_root_hash = str(root_hash or "").strip()
    if not normalized_root_hash:
        raise ValueError("root_hash is required")
    normalized_date = str(date_utc or "").strip()
    if not normalized_date:
        raise ValueError("date_utc is required")

    now = _utc_now_iso()
    with storage.transaction():
        existing = _get_job_by_root(tenant_id=effective_tenant, root_hash=normalized_root_hash)
        if existing:
            if (
                existing["status"] in RETRYABLE_STATUSES
                and int(existing.get("ledger_head_seq") or 0) < int(ledger_head_seq)
            ):
                storage.execute(
                    """
                    UPDATE anchor_jobs
                    SET ledger_head_seq = ?, updated_at = ?
                    WHERE tenant_id = ? AND job_id = ?
                    """,
                    (
                        int(ledger_head_seq),
                        now,
                        effective_tenant,
                        existing["job_id"],
                    ),
                )
                existing = get_anchor_job(tenant_id=effective_tenant, job_id=existing["job_id"])
            return existing

        job_id = str(uuid.uuid4())
        storage.execute(
            """
            INSERT INTO anchor_jobs (
                tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
                next_attempt_at, last_error, external_anchor_id, created_at, updated_at, submitted_at, confirmed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                job_id,
                normalized_root_hash,
                normalized_date,
                max(0, int(ledger_head_seq)),
                STATUS_PENDING,
                0,
                str(next_attempt_at or now),
                None,
                None,
                now,
                now,
                None,
                None,
            ),
        )
        created = get_anchor_job(tenant_id=effective_tenant, job_id=job_id)
        if not created:
            raise RuntimeError("failed to create anchor job")
        return created


def list_retryable_anchor_jobs(
    *,
    tenant_id: Optional[str] = None,
    now_utc: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    bounded_limit = max(1, min(int(limit), 500))
    cutoff = str(now_utc or _utc_now_iso())

    if tenant_id is None:
        rows = storage.fetchall(
            """
            SELECT tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
                   next_attempt_at, last_error, external_anchor_id, created_at, updated_at,
                   submitted_at, confirmed_at
            FROM anchor_jobs
            WHERE status IN ('PENDING', 'FAILED')
              AND next_attempt_at <= ?
            ORDER BY next_attempt_at ASC, created_at ASC
            LIMIT ?
            """,
            (cutoff, bounded_limit),
        )
    else:
        effective_tenant = resolve_tenant_id(tenant_id)
        rows = storage.fetchall(
            """
            SELECT tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
                   next_attempt_at, last_error, external_anchor_id, created_at, updated_at,
                   submitted_at, confirmed_at
            FROM anchor_jobs
            WHERE tenant_id = ?
              AND status IN ('PENDING', 'FAILED')
              AND next_attempt_at <= ?
            ORDER BY next_attempt_at ASC, created_at ASC
            LIMIT ?
            """,
            (effective_tenant, cutoff, bounded_limit),
        )
    return [_row_to_job(row) for row in rows]


def list_anchor_jobs(
    *,
    tenant_id: Optional[str],
    statuses: Optional[Sequence[str]] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_limit = max(1, min(int(limit), 1000))
    normalized_statuses = [
        _normalize_status(item)
        for item in (statuses or [])
        if _normalize_status(item)
    ]
    if normalized_statuses:
        placeholders = ",".join(["?"] * len(normalized_statuses))
        rows = storage.fetchall(
            f"""
            SELECT tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
                   next_attempt_at, last_error, external_anchor_id, created_at, updated_at,
                   submitted_at, confirmed_at
            FROM anchor_jobs
            WHERE tenant_id = ? AND status IN ({placeholders})
            ORDER BY created_at DESC
            LIMIT ?
            """,
            [effective_tenant, *normalized_statuses, bounded_limit],
        )
    else:
        rows = storage.fetchall(
            """
            SELECT tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
                   next_attempt_at, last_error, external_anchor_id, created_at, updated_at,
                   submitted_at, confirmed_at
            FROM anchor_jobs
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (effective_tenant, bounded_limit),
        )
    return [_row_to_job(row) for row in rows]


def get_latest_anchor_job(
    *,
    tenant_id: Optional[str],
    prefer_confirmed: bool = True,
) -> Optional[Dict[str, Any]]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    if prefer_confirmed:
        row = storage.fetchone(
            """
            SELECT tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
                   next_attempt_at, last_error, external_anchor_id, created_at, updated_at,
                   submitted_at, confirmed_at
            FROM anchor_jobs
            WHERE tenant_id = ? AND status = 'CONFIRMED'
            ORDER BY confirmed_at DESC, created_at DESC
            LIMIT 1
            """,
            (effective_tenant,),
        )
        if row:
            return _row_to_job(row)
    row = storage.fetchone(
        """
        SELECT tenant_id, job_id, root_hash, date_utc, ledger_head_seq, status, attempts,
               next_attempt_at, last_error, external_anchor_id, created_at, updated_at,
               submitted_at, confirmed_at
        FROM anchor_jobs
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (effective_tenant,),
    )
    if not row:
        return None
    return _row_to_job(row)


def list_transparency_tenants() -> List[str]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    rows = storage.fetchall(
        """
        SELECT DISTINCT tenant_id FROM audit_transparency_log
        UNION
        SELECT DISTINCT tenant_id FROM anchor_jobs
        ORDER BY tenant_id ASC
        """
    )
    tenants: List[str] = []
    for row in rows:
        value = str(row.get("tenant_id") or "").strip()
        if value:
            tenants.append(value)
    return tenants


def get_transparency_ledger_head(*, tenant_id: Optional[str]) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT COUNT(*) AS ledger_head_seq, MAX(issued_at) AS latest_issued_at
        FROM audit_transparency_log
        WHERE tenant_id = ?
        """,
        (effective_tenant,),
    ) or {}
    return {
        "tenant_id": effective_tenant,
        "ledger_head_seq": _to_int(row.get("ledger_head_seq"), 0),
        "latest_issued_at": row.get("latest_issued_at"),
    }


def mark_anchor_job_submitted(
    *,
    tenant_id: Optional[str],
    job_id: str,
    external_anchor_id: Optional[str],
    attempts: int,
    submitted_at: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now = str(submitted_at or _utc_now_iso())
    storage.execute(
        """
        UPDATE anchor_jobs
        SET status = ?, attempts = ?, external_anchor_id = ?, last_error = NULL,
            submitted_at = COALESCE(submitted_at, ?), updated_at = ?
        WHERE tenant_id = ? AND job_id = ?
        """,
        (
            STATUS_SUBMITTED,
            max(0, int(attempts)),
            str(external_anchor_id or "").strip() or None,
            now,
            now,
            effective_tenant,
            str(job_id),
        ),
    )
    return get_anchor_job(tenant_id=effective_tenant, job_id=job_id)


def mark_anchor_job_confirmed(
    *,
    tenant_id: Optional[str],
    job_id: str,
    confirmed_at: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now = str(confirmed_at or _utc_now_iso())
    storage.execute(
        """
        UPDATE anchor_jobs
        SET status = ?, confirmed_at = COALESCE(confirmed_at, ?), updated_at = ?, last_error = NULL
        WHERE tenant_id = ? AND job_id = ?
        """,
        (
            STATUS_CONFIRMED,
            now,
            now,
            effective_tenant,
            str(job_id),
        ),
    )
    return get_anchor_job(tenant_id=effective_tenant, job_id=job_id)


def mark_anchor_job_failed(
    *,
    tenant_id: Optional[str],
    job_id: str,
    attempts: int,
    next_attempt_at: str,
    last_error: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    ensure_anchor_jobs_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now = _utc_now_iso()
    storage.execute(
        """
        UPDATE anchor_jobs
        SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?, updated_at = ?
        WHERE tenant_id = ? AND job_id = ?
        """,
        (
            STATUS_FAILED,
            max(0, int(attempts)),
            str(next_attempt_at),
            str(last_error or "").strip()[:2048],
            now,
            effective_tenant,
            str(job_id),
        ),
    )
    return get_anchor_job(tenant_id=effective_tenant, job_id=job_id)
