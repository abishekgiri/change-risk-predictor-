from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import HTTPException


_LOCK = threading.Lock()
_BUCKETS: Dict[str, Deque[float]] = defaultdict(deque)


def _limit(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = int(raw)
        return parsed if parsed > 0 else default
    except Exception:
        return default


PROFILES = {
    "default": (
        _limit("RELEASEGATE_RATE_LIMIT_TENANT_DEFAULT", 180),
        _limit("RELEASEGATE_RATE_LIMIT_IP_DEFAULT", 300),
    ),
    "heavy": (
        _limit("RELEASEGATE_RATE_LIMIT_TENANT_HEAVY", 20),
        _limit("RELEASEGATE_RATE_LIMIT_IP_HEAVY", 40),
    ),
    "webhook": (
        _limit("RELEASEGATE_RATE_LIMIT_TENANT_WEBHOOK", 300),
        _limit("RELEASEGATE_RATE_LIMIT_IP_WEBHOOK", 600),
    ),
}

WINDOW_SECONDS = _limit("RELEASEGATE_RATE_LIMIT_WINDOW_SECONDS", 60)


def _check_bucket(key: str, max_calls: int) -> Tuple[bool, int]:
    now = time.time()
    with _LOCK:
        bucket = _BUCKETS[key]
        cutoff = now - WINDOW_SECONDS
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= max_calls:
            retry_after = max(1, int(round(WINDOW_SECONDS - (now - bucket[0]))))
            return False, retry_after
        bucket.append(now)
    return True, 0


def enforce_tenant_rate_limit(*, tenant_id: str, profile: str = "default") -> None:
    tenant_limit, _ = PROFILES.get(profile, PROFILES["default"])
    ok_tenant, retry_after_tenant = _check_bucket(f"tenant:{profile}:{tenant_id}", tenant_limit)
    if not ok_tenant:
        raise HTTPException(
            status_code=429,
            detail={
                "error_code": "RATE_LIMIT_TENANT",
                "message": "Tenant rate limit exceeded",
                "retry_after": retry_after_tenant,
            },
            headers={"Retry-After": str(retry_after_tenant)},
        )


def enforce_ip_rate_limit(*, ip: str, profile: str = "default") -> None:
    _, ip_limit = PROFILES.get(profile, PROFILES["default"])
    ok_ip, retry_after_ip = _check_bucket(f"ip:{profile}:{ip}", ip_limit)
    if not ok_ip:
        raise HTTPException(
            status_code=429,
            detail={
                "error_code": "RATE_LIMIT_IP",
                "message": "IP rate limit exceeded",
                "retry_after": retry_after_ip,
            },
            headers={"Retry-After": str(retry_after_ip)},
        )


def enforce_rate_limit(*, tenant_id: str, ip: str, profile: str = "default") -> None:
    enforce_tenant_rate_limit(tenant_id=tenant_id, profile=profile)
    enforce_ip_rate_limit(ip=ip, profile=profile)


def reset_rate_limits() -> None:
    with _LOCK:
        _BUCKETS.clear()
