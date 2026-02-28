from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from releasegate.anchoring.anchor_service import (
    ensure_due_anchor_job,
    list_scheduler_tenants,
    process_retryable_anchor_jobs,
)
from releasegate.config import is_anchoring_enabled
from releasegate.storage import get_storage_backend


logger = logging.getLogger(__name__)

_LOCAL_TICK_LOCK = threading.Lock()
_SCHEDULER_THREAD: Optional[threading.Thread] = None
_STOP_EVENT = threading.Event()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = str(raw).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except Exception:
        return default


def _advisory_lock_id(lock_scope: str) -> int:
    digest = hashlib.sha256(lock_scope.encode("utf-8")).digest()
    value = int.from_bytes(digest[:8], byteorder="big", signed=False)
    return value & ((1 << 63) - 1)


def _with_scheduler_lock(*, lock_scope: str, fn: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
    if not _LOCAL_TICK_LOCK.acquire(blocking=False):
        return {"ok": True, "skipped": True, "reason": "LOCAL_LOCK_HELD"}
    try:
        storage = get_storage_backend()
        if storage.name != "postgres":
            return fn()

        lock_id = _advisory_lock_id(lock_scope)
        with storage.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_try_advisory_lock(%s)", (lock_id,))
                row = cur.fetchone()
                if not row or not bool(row[0]):
                    return {"ok": True, "skipped": True, "reason": "POSTGRES_LOCK_HELD"}
            try:
                return fn()
            finally:
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (lock_id,))
                conn.commit()
    finally:
        _LOCAL_TICK_LOCK.release()


def tick(*, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    if not is_anchoring_enabled():
        return {
            "ok": True,
            "anchoring_enabled": False,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tenants": [],
        }

    scope = f"releasegate:anchor_tick:{tenant_id or '*'}"

    def _run_tick() -> Dict[str, Any]:
        tenants = list_scheduler_tenants(tenant_id=tenant_id)
        job_batch_size = _env_int("RELEASEGATE_ANCHOR_JOB_BATCH_SIZE", 20)
        report = {
            "ok": True,
            "anchoring_enabled": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tenant_count": len(tenants),
            "tenants": [],
        }
        for tenant in tenants:
            enqueue = ensure_due_anchor_job(tenant_id=tenant)
            processing = process_retryable_anchor_jobs(tenant_id=tenant, limit=job_batch_size)
            report["tenants"].append(
                {
                    "tenant_id": tenant,
                    "enqueue": enqueue,
                    "processing": processing,
                }
            )
        return report

    return _with_scheduler_lock(lock_scope=scope, fn=_run_tick)


def _scheduler_loop() -> None:
    interval_seconds = _env_int("RELEASEGATE_ANCHOR_SCHEDULER_INTERVAL_SECONDS", 900)
    while not _STOP_EVENT.wait(max(1, interval_seconds)):
        try:
            tick()
        except Exception:
            logger.exception("anchor scheduler tick failed")


def start_anchor_scheduler() -> Dict[str, Any]:
    global _SCHEDULER_THREAD
    if not _env_bool("RELEASEGATE_ANCHOR_SCHEDULER_ENABLED", False):
        return {"started": False, "reason": "DISABLED"}
    if _SCHEDULER_THREAD is not None and _SCHEDULER_THREAD.is_alive():
        return {"started": True, "reason": "ALREADY_RUNNING"}
    _STOP_EVENT.clear()
    thread = threading.Thread(target=_scheduler_loop, name="releasegate-anchor-scheduler", daemon=True)
    thread.start()
    _SCHEDULER_THREAD = thread
    return {"started": True, "reason": "STARTED"}


def stop_anchor_scheduler() -> Dict[str, Any]:
    global _SCHEDULER_THREAD
    if _SCHEDULER_THREAD is None:
        return {"stopped": True, "reason": "NOT_RUNNING"}
    _STOP_EVENT.set()
    _SCHEDULER_THREAD.join(timeout=2.0)
    _SCHEDULER_THREAD = None
    return {"stopped": True, "reason": "STOPPED"}


def scheduler_status() -> Dict[str, Any]:
    running = _SCHEDULER_THREAD is not None and _SCHEDULER_THREAD.is_alive()
    return {
        "enabled": _env_bool("RELEASEGATE_ANCHOR_SCHEDULER_ENABLED", False),
        "running": running,
        "interval_seconds": _env_int("RELEASEGATE_ANCHOR_SCHEDULER_INTERVAL_SECONDS", 900),
    }
