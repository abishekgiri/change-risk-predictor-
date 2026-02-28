from __future__ import annotations

import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from releasegate.anchoring.models import (
    STATUS_CONFIRMED,
    STATUS_FAILED,
    get_latest_anchor_job,
    get_transparency_ledger_head,
    list_retryable_anchor_jobs,
    list_transparency_tenants,
    mark_anchor_job_confirmed,
    mark_anchor_job_failed,
    mark_anchor_job_submitted,
    upsert_anchor_job,
)
from releasegate.anchoring.provider import verify_root_anchor_receipt
from releasegate.anchoring.roots import anchor_transparency_root, get_root_anchor_by_target
from releasegate.config import get_anchor_provider_name, is_anchoring_enabled
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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _latest_transparency_date(tenant_id: str) -> Optional[str]:
    ledger = get_transparency_ledger_head(tenant_id=tenant_id)
    latest_issued_at = ledger.get("latest_issued_at")
    latest = _parse_iso_datetime(latest_issued_at)
    if latest is None:
        return None
    return latest.date().isoformat()


def compute_current_anchor_target(*, tenant_id: str) -> Optional[Dict[str, Any]]:
    ledger = get_transparency_ledger_head(tenant_id=tenant_id)
    date_utc = _latest_transparency_date(tenant_id)
    if not date_utc:
        return None
    from releasegate.audit.transparency import get_or_compute_transparency_root

    root_entry = get_or_compute_transparency_root(date_utc=date_utc, tenant_id=tenant_id)
    if not root_entry:
        return None
    root_hash = str(root_entry.get("root_hash") or "").strip()
    if not root_hash:
        return None
    return {
        "tenant_id": tenant_id,
        "date_utc": date_utc,
        "root_hash": root_hash,
        "ledger_head_seq": int(ledger.get("ledger_head_seq") or 0),
    }


def is_anchoring_due(*, tenant_id: str, now_utc: Optional[datetime] = None) -> Dict[str, Any]:
    now = now_utc or _now_utc()
    target = compute_current_anchor_target(tenant_id=tenant_id)
    if not target:
        return {"due": False, "reason": "NO_TRANSPARENCY_ROOT", "target": None}

    latest_confirmed = get_latest_anchor_job(tenant_id=tenant_id, prefer_confirmed=True)
    if not latest_confirmed or latest_confirmed.get("status") != STATUS_CONFIRMED:
        return {"due": True, "reason": "NO_CONFIRMED_ANCHOR", "target": target}

    if str(latest_confirmed.get("root_hash") or "") != str(target["root_hash"]):
        return {"due": True, "reason": "ROOT_CHANGED", "target": target}

    interval_hours = _env_int("RELEASEGATE_ANCHOR_INTERVAL_HOURS", 6)
    confirmed_at = _parse_iso_datetime(latest_confirmed.get("confirmed_at"))
    if confirmed_at is None:
        return {"due": True, "reason": "CONFIRMED_AT_MISSING", "target": target}
    if now - confirmed_at >= timedelta(hours=max(1, interval_hours)):
        return {"due": True, "reason": "INTERVAL_ELAPSED", "target": target}

    delta_threshold = _env_int("RELEASEGATE_ANCHOR_EVENT_THRESHOLD", 100)
    current_head_seq = int(target.get("ledger_head_seq") or 0)
    anchored_head_seq = int(latest_confirmed.get("ledger_head_seq") or 0)
    if current_head_seq - anchored_head_seq >= max(1, delta_threshold):
        return {"due": True, "reason": "LEDGER_DELTA_THRESHOLD", "target": target}

    return {"due": False, "reason": "FRESH", "target": target}


def ensure_due_anchor_job(*, tenant_id: str, now_utc: Optional[datetime] = None) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    due_report = is_anchoring_due(tenant_id=effective_tenant, now_utc=now_utc)
    target = due_report.get("target")
    if not due_report.get("due") or not isinstance(target, dict):
        return {
            "tenant_id": effective_tenant,
            "due": bool(due_report.get("due")),
            "reason": str(due_report.get("reason") or ""),
            "target": target,
            "job": None,
        }
    job = upsert_anchor_job(
        tenant_id=effective_tenant,
        root_hash=str(target.get("root_hash") or ""),
        date_utc=str(target.get("date_utc") or ""),
        ledger_head_seq=int(target.get("ledger_head_seq") or 0),
        next_attempt_at=(now_utc or _now_utc()).isoformat(),
    )
    return {
        "tenant_id": effective_tenant,
        "due": True,
        "reason": str(due_report.get("reason") or ""),
        "target": target,
        "job": job,
    }


def compute_backoff_seconds(*, attempts: int) -> int:
    base_seconds = _env_int("RELEASEGATE_ANCHOR_RETRY_BASE_SECONDS", 30)
    max_seconds = _env_int("RELEASEGATE_ANCHOR_RETRY_MAX_SECONDS", 3600)
    jitter_pct = float(os.getenv("RELEASEGATE_ANCHOR_RETRY_JITTER_PCT", "0.10") or "0.10")
    exp = max(0, int(attempts) - 1)
    raw = min(max_seconds, base_seconds * (2**exp))
    jitter_range = max(0.0, min(1.0, jitter_pct))
    if jitter_range > 0:
        delta = raw * jitter_range
        raw = max(1.0, raw + random.uniform(-delta, delta))
    return max(1, int(round(raw)))


def process_anchor_job(job: Dict[str, Any]) -> Dict[str, Any]:
    tenant_id = resolve_tenant_id(job.get("tenant_id"))
    provider_name = get_anchor_provider_name()
    now = _now_utc()
    previous_attempts = int(job.get("attempts") or 0)
    attempt_number = previous_attempts + 1
    max_attempts = _env_int("RELEASEGATE_ANCHOR_MAX_ATTEMPTS", 10)
    if attempt_number > max_attempts:
        next_attempt = now + timedelta(seconds=compute_backoff_seconds(attempts=max_attempts))
        failed = mark_anchor_job_failed(
            tenant_id=tenant_id,
            job_id=str(job["job_id"]),
            attempts=previous_attempts,
            next_attempt_at=next_attempt.isoformat(),
            last_error="maximum anchoring attempts reached",
        )
        return {
            "ok": False,
            "tenant_id": tenant_id,
            "job": failed,
            "error": "ANCHOR_MAX_ATTEMPTS_REACHED",
        }

    try:
        existing_anchor = get_root_anchor_by_target(
            tenant_id=tenant_id,
            provider=provider_name,
            date_utc=str(job.get("date_utc") or ""),
            root_hash=str(job.get("root_hash") or ""),
        )
        anchored = existing_anchor
        if not anchored:
            anchored = anchor_transparency_root(
                date_utc=str(job.get("date_utc") or ""),
                tenant_id=tenant_id,
                provider_name=provider_name,
            )
        if not anchored:
            raise RuntimeError("root anchor could not be created for requested date")
        if str(anchored.get("root_hash") or "") != str(job.get("root_hash") or ""):
            raise RuntimeError("anchored root hash mismatch for job target")

        submitted = mark_anchor_job_submitted(
            tenant_id=tenant_id,
            job_id=str(job["job_id"]),
            external_anchor_id=str(
                anchored.get("external_ref")
                or anchored.get("anchor_id")
                or ""
            ).strip()
            or None,
            attempts=attempt_number,
            submitted_at=now.isoformat(),
        )
        receipt = anchored.get("receipt") if isinstance(anchored.get("receipt"), dict) else {}
        provider = str(anchored.get("provider") or provider_name).strip().lower()
        if receipt and verify_root_anchor_receipt(
            receipt=receipt,
            expected_root_hash=str(job.get("root_hash") or ""),
            provider_name=provider,
        ):
            confirmed = mark_anchor_job_confirmed(
                tenant_id=tenant_id,
                job_id=str(job["job_id"]),
                confirmed_at=now.isoformat(),
            )
            return {
                "ok": True,
                "tenant_id": tenant_id,
                "job": confirmed or submitted,
                "anchor": anchored,
            }
        raise RuntimeError("anchor receipt verification failed")
    except Exception as exc:
        next_attempt = now + timedelta(seconds=compute_backoff_seconds(attempts=attempt_number))
        failed = mark_anchor_job_failed(
            tenant_id=tenant_id,
            job_id=str(job["job_id"]),
            attempts=attempt_number,
            next_attempt_at=next_attempt.isoformat(),
            last_error=str(exc),
        )
        return {
            "ok": False,
            "tenant_id": tenant_id,
            "job": failed,
            "error": str(exc),
        }


def process_retryable_anchor_jobs(
    *,
    tenant_id: Optional[str],
    limit: int = 20,
) -> Dict[str, Any]:
    if not is_anchoring_enabled():
        return {"ok": True, "processed": 0, "results": [], "anchoring_enabled": False}
    jobs = list_retryable_anchor_jobs(tenant_id=tenant_id, limit=limit)
    results: List[Dict[str, Any]] = []
    for job in jobs:
        results.append(process_anchor_job(job))
    return {
        "ok": True,
        "processed": len(results),
        "results": results,
        "anchoring_enabled": True,
    }


def list_scheduler_tenants(*, tenant_id: Optional[str] = None) -> List[str]:
    if tenant_id:
        return [resolve_tenant_id(tenant_id)]
    tenants = list_transparency_tenants()
    if tenants:
        return tenants
    fallback = resolve_tenant_id(None, allow_none=True)
    return [fallback] if fallback else []
