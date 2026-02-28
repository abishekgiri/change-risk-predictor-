from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple

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


_TENANT_DEFAULT_MINUTE = _limit("RELEASEGATE_RATE_LIMIT_TENANT_DEFAULT", 180)
_TENANT_DEFAULT_HOUR = _limit("RELEASEGATE_RATE_LIMIT_TENANT_DEFAULT_HOURLY", _TENANT_DEFAULT_MINUTE * 10)
_IP_DEFAULT_MINUTE = _limit("RELEASEGATE_RATE_LIMIT_IP_DEFAULT", 300)
_IP_DEFAULT_HOUR = _limit("RELEASEGATE_RATE_LIMIT_IP_DEFAULT_HOURLY", _IP_DEFAULT_MINUTE * 10)

_TENANT_HEAVY_MINUTE = _limit("RELEASEGATE_RATE_LIMIT_TENANT_HEAVY", 20)
_TENANT_HEAVY_HOUR = _limit("RELEASEGATE_RATE_LIMIT_TENANT_HEAVY_HOURLY", _TENANT_HEAVY_MINUTE * 12)
_IP_HEAVY_MINUTE = _limit("RELEASEGATE_RATE_LIMIT_IP_HEAVY", 40)
_IP_HEAVY_HOUR = _limit("RELEASEGATE_RATE_LIMIT_IP_HEAVY_HOURLY", _IP_HEAVY_MINUTE * 12)

_TENANT_WEBHOOK_MINUTE = _limit("RELEASEGATE_RATE_LIMIT_TENANT_WEBHOOK", 300)
_TENANT_WEBHOOK_HOUR = _limit("RELEASEGATE_RATE_LIMIT_TENANT_WEBHOOK_HOURLY", _TENANT_WEBHOOK_MINUTE * 10)
_IP_WEBHOOK_MINUTE = _limit("RELEASEGATE_RATE_LIMIT_IP_WEBHOOK", 600)
_IP_WEBHOOK_HOUR = _limit("RELEASEGATE_RATE_LIMIT_IP_WEBHOOK_HOURLY", _IP_WEBHOOK_MINUTE * 10)
_ISSUE_WEBHOOK_MINUTE = _limit("RELEASEGATE_RATE_LIMIT_ISSUE_WEBHOOK", 120)
_ISSUE_WEBHOOK_HOUR = _limit("RELEASEGATE_RATE_LIMIT_ISSUE_WEBHOOK_HOURLY", _ISSUE_WEBHOOK_MINUTE * 10)

PROFILES = {
    "default": {
        "tenant": [(_TENANT_DEFAULT_MINUTE, 60), (_TENANT_DEFAULT_HOUR, 3600)],
        "ip": [(_IP_DEFAULT_MINUTE, 60), (_IP_DEFAULT_HOUR, 3600)],
        "issue": [],
    },
    "heavy": {
        "tenant": [(_TENANT_HEAVY_MINUTE, 60), (_TENANT_HEAVY_HOUR, 3600)],
        "ip": [(_IP_HEAVY_MINUTE, 60), (_IP_HEAVY_HOUR, 3600)],
        "issue": [],
    },
    "webhook": {
        "tenant": [(_TENANT_WEBHOOK_MINUTE, 60), (_TENANT_WEBHOOK_HOUR, 3600)],
        "ip": [(_IP_WEBHOOK_MINUTE, 60), (_IP_WEBHOOK_HOUR, 3600)],
        "issue": [(_ISSUE_WEBHOOK_MINUTE, 60), (_ISSUE_WEBHOOK_HOUR, 3600)],
    },
}

WINDOW_SECONDS = _limit("RELEASEGATE_RATE_LIMIT_WINDOW_SECONDS", 60)


def _profile_windows(profile: str, scope: str) -> List[Tuple[int, int]]:
    selected = PROFILES.get(profile, PROFILES["default"])
    if isinstance(selected, tuple):
        tenant_limit, ip_limit = selected
        limit = tenant_limit if scope == "tenant" else ip_limit
        return [(max(1, int(limit)), max(1, int(WINDOW_SECONDS)))]
    if not isinstance(selected, dict):
        fallback = PROFILES["default"]
        selected = fallback if isinstance(fallback, dict) else {}
    values = selected.get(scope, [])
    if isinstance(values, int):
        return [(max(1, int(values)), max(1, int(WINDOW_SECONDS)))]
    normalized: List[Tuple[int, int]] = []
    if isinstance(values, list):
        for item in values:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            try:
                limit = max(1, int(item[0]))
                window = max(1, int(item[1]))
            except Exception:
                continue
            normalized.append((limit, window))
    if normalized:
        return normalized
    if scope == "issue":
        return []
    fallback_scope = "tenant" if scope == "tenant" else "ip"
    fallback_windows = selected.get(fallback_scope, [])
    if isinstance(fallback_windows, list):
        for item in fallback_windows:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                try:
                    normalized.append((max(1, int(item[0])), max(1, int(item[1]))))
                except Exception:
                    continue
    return normalized or [(max(1, int(_limit("RELEASEGATE_RATE_LIMIT_FALLBACK", 100))), max(1, int(WINDOW_SECONDS)))]


def _check_bucket(key: str, max_calls: int, window_seconds: int) -> Tuple[bool, int]:
    now = time.time()
    bucket_key = f"{key}:w{int(window_seconds)}"
    with _LOCK:
        bucket = _BUCKETS[bucket_key]
        cutoff = now - window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= max_calls:
            retry_after = max(1, int(round(window_seconds - (now - bucket[0]))))
            return False, retry_after
        bucket.append(now)
    return True, 0


def _enforce_windows(*, key_prefix: str, windows: List[Tuple[int, int]], error_code: str, message: str) -> None:
    for limit, window_seconds in windows:
        ok, retry_after = _check_bucket(key_prefix, limit, window_seconds)
        if ok:
            continue
        raise HTTPException(
            status_code=429,
            detail={
                "error_code": error_code,
                "message": message,
                "retry_after": retry_after,
                "window_seconds": window_seconds,
                "limit": limit,
            },
            headers={"Retry-After": str(retry_after)},
        )


def enforce_tenant_rate_limit(*, tenant_id: str, profile: str = "default") -> None:
    windows = _profile_windows(profile, "tenant")
    _enforce_windows(
        key_prefix=f"tenant:{profile}:{tenant_id}",
        windows=windows,
        error_code="RATE_LIMIT_TENANT",
        message="Tenant rate limit exceeded",
    )


def enforce_ip_rate_limit(*, ip: str, profile: str = "default") -> None:
    windows = _profile_windows(profile, "ip")
    _enforce_windows(
        key_prefix=f"ip:{profile}:{ip}",
        windows=windows,
        error_code="RATE_LIMIT_IP",
        message="IP rate limit exceeded",
    )


def enforce_issue_rate_limit(*, tenant_id: str, issue_key: str, profile: str = "webhook") -> None:
    normalized_issue = str(issue_key or "").strip().upper()
    if not normalized_issue:
        return
    windows = _profile_windows(profile, "issue")
    if not windows:
        return
    _enforce_windows(
        key_prefix=f"issue:{profile}:{tenant_id}:{normalized_issue}",
        windows=windows,
        error_code="RATE_LIMIT_ISSUE",
        message="Issue transition rate limit exceeded",
    )


def enforce_rate_limit(*, tenant_id: str, ip: str, profile: str = "default") -> None:
    enforce_tenant_rate_limit(tenant_id=tenant_id, profile=profile)
    enforce_ip_rate_limit(ip=ip, profile=profile)


def reset_rate_limits() -> None:
    with _LOCK:
        _BUCKETS.clear()
