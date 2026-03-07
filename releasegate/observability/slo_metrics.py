from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Deque, Dict


_STARTED_AT = datetime.now(timezone.utc)
_LOCK = Lock()
_MAX_LATENCY_SAMPLES = 5000
_LATENCY_MS: Deque[float] = deque(maxlen=_MAX_LATENCY_SAMPLES)
_COUNTERS = Counter()
_ROUTE_LATENCY_MS: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=_MAX_LATENCY_SAMPLES))
_ROUTE_COUNTERS: Dict[str, Counter] = defaultdict(Counter)


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if percentile <= 0:
        return float(values[0])
    if percentile >= 100:
        return float(values[-1])
    index = int(round((percentile / 100.0) * (len(values) - 1)))
    return float(values[index])


def record_http_request(*, path: str, method: str, status_code: int, latency_ms: float) -> None:
    route_key = str(path or "/").strip() or "/"
    normalized_status = int(status_code)
    latency_value = max(0.0, float(latency_ms))
    with _LOCK:
        _LATENCY_MS.append(latency_value)
        _COUNTERS["http_requests_total"] += 1
        _COUNTERS[f"http_status_{normalized_status}_total"] += 1
        _COUNTERS[f"http_method_{str(method or 'unknown').upper()}_total"] += 1
        _COUNTERS[f"http_path_{route_key}_total"] += 1
        _ROUTE_LATENCY_MS[route_key].append(latency_value)
        _ROUTE_COUNTERS[route_key]["http_requests_total"] += 1
        _ROUTE_COUNTERS[route_key][f"http_status_{normalized_status}_total"] += 1
        if normalized_status >= 500:
            _COUNTERS["http_errors_5xx_total"] += 1
            _ROUTE_COUNTERS[route_key]["http_errors_5xx_total"] += 1
        if normalized_status >= 400:
            _COUNTERS["http_errors_4xx5xx_total"] += 1
            _ROUTE_COUNTERS[route_key]["http_errors_4xx5xx_total"] += 1


def snapshot() -> Dict[str, Any]:
    with _LOCK:
        counts = dict(_COUNTERS)
        latency_sorted = sorted(_LATENCY_MS)
        route_counts = {path: dict(counter) for path, counter in _ROUTE_COUNTERS.items()}
        route_latency = {path: sorted(samples) for path, samples in _ROUTE_LATENCY_MS.items()}
    total = int(counts.get("http_requests_total", 0))
    errors_5xx = int(counts.get("http_errors_5xx_total", 0))
    errors_4xx5xx = int(counts.get("http_errors_4xx5xx_total", 0))
    error_rate_5xx = (float(errors_5xx) / float(total)) if total > 0 else 0.0
    error_rate_4xx5xx = (float(errors_4xx5xx) / float(total)) if total > 0 else 0.0
    now = datetime.now(timezone.utc)
    uptime_seconds = max(0.0, (now - _STARTED_AT).total_seconds())
    routes: Dict[str, Dict[str, Any]] = {}
    for path in sorted(route_counts.keys()):
        path_counts = route_counts.get(path) or {}
        path_latency = route_latency.get(path) or []
        path_total = int(path_counts.get("http_requests_total", 0))
        path_errors_5xx = int(path_counts.get("http_errors_5xx_total", 0))
        path_errors_4xx5xx = int(path_counts.get("http_errors_4xx5xx_total", 0))
        routes[path] = {
            "http_requests_total": path_total,
            "http_errors_5xx_total": path_errors_5xx,
            "http_errors_4xx5xx_total": path_errors_4xx5xx,
            "http_error_rate_5xx": round((float(path_errors_5xx) / float(path_total)) if path_total > 0 else 0.0, 6),
            "http_error_rate_4xx5xx": round(
                (float(path_errors_4xx5xx) / float(path_total)) if path_total > 0 else 0.0,
                6,
            ),
            "latency_samples": len(path_latency),
            "latency_ms_p50": round(_percentile(path_latency, 50), 3),
            "latency_ms_p95": round(_percentile(path_latency, 95), 3),
            "latency_ms_p99": round(_percentile(path_latency, 99), 3),
        }
    return {
        "generated_at": now.isoformat(),
        "started_at": _STARTED_AT.isoformat(),
        "uptime_seconds": round(uptime_seconds, 3),
        "http_requests_total": total,
        "http_errors_5xx_total": errors_5xx,
        "http_errors_4xx5xx_total": errors_4xx5xx,
        "http_error_rate_5xx": round(error_rate_5xx, 6),
        "http_error_rate_4xx5xx": round(error_rate_4xx5xx, 6),
        "latency_samples": len(latency_sorted),
        "latency_ms_p50": round(_percentile(latency_sorted, 50), 3),
        "latency_ms_p95": round(_percentile(latency_sorted, 95), 3),
        "latency_ms_p99": round(_percentile(latency_sorted, 99), 3),
        "counters": counts,
        "routes": routes,
    }
