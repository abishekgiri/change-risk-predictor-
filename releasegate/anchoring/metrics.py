from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from releasegate.anchoring.models import (
    STATUS_CONFIRMED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_SUBMITTED,
    get_latest_anchor_job,
    get_transparency_ledger_head,
    list_anchor_jobs,
    list_transparency_tenants,
)
from releasegate.storage.base import resolve_tenant_id


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except Exception:
        return default


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except Exception:
            return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _consecutive_failures(jobs_desc: List[Dict[str, Any]]) -> int:
    streak = 0
    for job in jobs_desc:
        if str(job.get("status") or "").upper() == STATUS_FAILED:
            streak += 1
            continue
        break
    return streak


def get_anchor_health(*, tenant_id: Optional[str]) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    now = datetime.now(timezone.utc)
    max_age_hours = _env_int("RELEASEGATE_ANCHOR_HEALTH_MAX_AGE_HOURS", 24)
    max_failure_streak = _env_int("RELEASEGATE_ANCHOR_HEALTH_FAILURE_STREAK", 3)
    drift_threshold = _env_int("RELEASEGATE_ANCHOR_HEALTH_DRIFT_THRESHOLD", 200)
    failure_window_hours = _env_int("RELEASEGATE_ANCHOR_HEALTH_FAILURE_WINDOW_HOURS", 24)

    latest_confirmed = get_latest_anchor_job(tenant_id=effective_tenant, prefer_confirmed=True)
    latest_any = get_latest_anchor_job(tenant_id=effective_tenant, prefer_confirmed=False)
    if latest_confirmed and str(latest_confirmed.get("status") or "").upper() != STATUS_CONFIRMED:
        latest_confirmed = None
    jobs = list_anchor_jobs(tenant_id=effective_tenant, limit=500)
    latest_jobs_desc = list(jobs)
    created_cutoff = now - timedelta(hours=max(1, failure_window_hours))
    window_jobs = []
    for job in jobs:
        created_at = _parse_iso_datetime(job.get("created_at"))
        if created_at is not None and created_at >= created_cutoff:
            window_jobs.append(job)

    counts = {
        STATUS_PENDING: 0,
        STATUS_SUBMITTED: 0,
        STATUS_CONFIRMED: 0,
        STATUS_FAILED: 0,
    }
    for job in jobs:
        status = str(job.get("status") or "").upper()
        if status in counts:
            counts[status] += 1

    failure_jobs = [job for job in window_jobs if str(job.get("status") or "").upper() == STATUS_FAILED]
    total_window_jobs = len(window_jobs)
    failure_rate = 0.0
    if total_window_jobs > 0:
        failure_rate = len(failure_jobs) / float(total_window_jobs)

    consecutive_failures = _consecutive_failures(latest_jobs_desc)

    ledger_head = get_transparency_ledger_head(tenant_id=effective_tenant)
    ledger_head_seq = int(ledger_head.get("ledger_head_seq") or 0)
    anchored_seq = int((latest_confirmed or {}).get("ledger_head_seq") or 0)
    drift_events = max(0, ledger_head_seq - anchored_seq)

    last_anchor_time = None
    last_anchor_hash = None
    if latest_confirmed:
        last_anchor_time = latest_confirmed.get("confirmed_at") or latest_confirmed.get("submitted_at")
        last_anchor_hash = latest_confirmed.get("root_hash")
    elif latest_any:
        last_anchor_time = latest_any.get("submitted_at") or latest_any.get("created_at")
        last_anchor_hash = latest_any.get("root_hash")

    reasons: List[str] = []
    is_healthy = True

    if ledger_head_seq > 0 and not latest_confirmed:
        is_healthy = False
        reasons.append("NO_CONFIRMED_ANCHOR")

    last_anchor_dt = _parse_iso_datetime(last_anchor_time)
    if last_anchor_dt is not None:
        if now - last_anchor_dt > timedelta(hours=max(1, max_age_hours)):
            is_healthy = False
            reasons.append("ANCHOR_TOO_OLD")
    elif ledger_head_seq > 0:
        is_healthy = False
        reasons.append("ANCHOR_TIMESTAMP_MISSING")

    if consecutive_failures >= max(1, max_failure_streak):
        is_healthy = False
        reasons.append("CONSECUTIVE_FAILURES")

    if drift_events >= max(1, drift_threshold):
        is_healthy = False
        reasons.append("ANCHOR_DRIFT")

    return {
        "tenant_id": effective_tenant,
        "generated_at": now.isoformat(),
        "is_healthy": is_healthy,
        "reasons": reasons,
        "last_anchor_time": last_anchor_time,
        "last_anchor_hash": last_anchor_hash,
        "anchor_failure_rate": failure_rate,
        "counts": {
            "pending_count": counts[STATUS_PENDING],
            "submitted_count": counts[STATUS_SUBMITTED],
            "confirmed_count": counts[STATUS_CONFIRMED],
            "failed_count": counts[STATUS_FAILED],
        },
        "consecutive_failures": consecutive_failures,
        "ledger_head_seq": ledger_head_seq,
        "anchored_head_seq": anchored_seq,
        "drift_events": drift_events,
    }


def get_anchor_health_all() -> Dict[str, Any]:
    tenants = list_transparency_tenants()
    reports = [get_anchor_health(tenant_id=tenant) for tenant in tenants]
    unhealthy = [item for item in reports if not bool(item.get("is_healthy"))]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(reports),
        "unhealthy_count": len(unhealthy),
        "items": reports,
    }
