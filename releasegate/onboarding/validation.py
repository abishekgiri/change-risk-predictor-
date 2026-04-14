from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
from statistics import median
from typing import Any, Dict, Iterable, List, Optional

from releasegate.storage import get_storage_backend


RELEVANT_METRICS = (
    "onboarding_jira_connected",
    "onboarding_transition_scope_ready",
    "onboarding_first_value_ready",
    "onboarding_time_to_first_value_seconds",
    "onboarding_snapshot_shown",
    "onboarding_snapshot_hesitation_seconds",
    "onboarding_canary_enabled",
    "onboarding_time_to_canary_seconds",
    "onboarding_zero_transition_guard_triggered",
    "onboarding_protection_rolled_back",
)


def _window_start(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _load_metadata(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if raw in (None, ""):
        return {}
    try:
        parsed = json.loads(str(raw))
    except (TypeError, ValueError):
        return {}
    return dict(parsed) if isinstance(parsed, dict) else {}


def _median(values: Iterable[int]) -> Optional[float]:
    items = [int(value) for value in values]
    if not items:
        return None
    return float(median(items))


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return float(numerator / denominator)


def _pct_at_least(numerator: int, denominator: int, threshold_percent: int) -> bool:
    if denominator <= 0:
        return False
    return int(numerator) * 100 >= int(threshold_percent) * int(denominator)


def _pct_below(numerator: int, denominator: int, threshold_percent: int) -> bool:
    if denominator <= 0:
        return False
    return int(numerator) * 100 < int(threshold_percent) * int(denominator)


def _hesitation_band(seconds: Optional[int]) -> Optional[str]:
    if seconds is None:
        return None
    if seconds < 3:
        return "instant_trust"
    if seconds <= 10:
        return "acceptable_thinking"
    return "hesitation_or_doubt"


def _confidence_signal(total_transitions: Optional[int]) -> Optional[str]:
    if total_transitions is None:
        return None
    if total_transitions >= 75:
        return "high"
    if total_transitions >= 25:
        return "medium"
    return "growing"


def _cohort(*, first_value_ready: bool, canary_enabled: bool, hesitation_seconds: Optional[int]) -> str:
    if canary_enabled and hesitation_seconds is not None and hesitation_seconds < 5:
        return "ideal_flow"
    if canary_enabled and hesitation_seconds is not None and hesitation_seconds <= 10:
        return "converted_after_thinking"
    if canary_enabled:
        return "needs_clarity"
    if first_value_ready and not canary_enabled and hesitation_seconds is not None and hesitation_seconds > 10:
        return "activation_drop_off"
    if first_value_ready and not canary_enabled:
        return "stalled_after_value"
    return "stalled_before_value"


def build_phase1_validation_report(
    *,
    days: int = 30,
    tenant_id: Optional[str] = None,
    tenant_prefix: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    if int(days) < 1:
        raise ValueError("days must be at least 1")
    if int(limit) < 1:
        raise ValueError("limit must be at least 1")

    placeholders = ",".join("?" for _ in RELEVANT_METRICS)
    query = f"""
        SELECT tenant_id, metric_name, metric_value, created_at, metadata_json
        FROM metrics_events
        WHERE created_at >= ?
          AND metric_name IN ({placeholders})
    """
    params: List[Any] = [_window_start(days), *RELEVANT_METRICS]
    if str(tenant_id or "").strip():
        query += " AND tenant_id = ?"
        params.append(str(tenant_id).strip())
    elif str(tenant_prefix or "").strip():
        query += " AND tenant_id LIKE ?"
        params.append(f"{str(tenant_prefix).strip()}%")
    query += " ORDER BY tenant_id ASC, metric_name ASC, created_at DESC"

    rows = get_storage_backend().fetchall(query, params)
    latest_events: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    event_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        resolved_tenant = str(row.get("tenant_id") or "").strip()
        metric_name = str(row.get("metric_name") or "").strip()
        if not resolved_tenant or not metric_name:
            continue
        event_counts[resolved_tenant][metric_name] += 1
        if metric_name in latest_events[resolved_tenant]:
            continue
        latest_events[resolved_tenant][metric_name] = {
            "metric_value": int(row.get("metric_value") or 0),
            "created_at": str(row.get("created_at") or "") or None,
            "metadata": _load_metadata(row.get("metadata_json")),
        }

    sessions: List[Dict[str, Any]] = []
    for resolved_tenant, metrics in latest_events.items():
        snapshot_metadata: Dict[str, Any] = {}
        for metric_name in (
            "onboarding_snapshot_shown",
            "onboarding_snapshot_hesitation_seconds",
            "onboarding_first_value_ready",
        ):
            snapshot_metadata.update(dict((metrics.get(metric_name) or {}).get("metadata") or {}))
        total_transitions_value = snapshot_metadata.get("total_transitions")
        total_transitions: Optional[int] = None
        if total_transitions_value is not None:
            try:
                total_transitions = int(total_transitions_value)
            except (TypeError, ValueError):
                total_transitions = None

        time_to_first_value = metrics.get("onboarding_time_to_first_value_seconds")
        time_to_canary = metrics.get("onboarding_time_to_canary_seconds")
        hesitation = metrics.get("onboarding_snapshot_hesitation_seconds")
        first_value_ready = bool(metrics.get("onboarding_first_value_ready"))
        canary_enabled = bool(metrics.get("onboarding_canary_enabled"))
        hesitation_seconds = int(hesitation.get("metric_value") or 0) if hesitation else None

        sessions.append(
            {
                "tenant_id": resolved_tenant,
                "jira_connected_at": (metrics.get("onboarding_jira_connected") or {}).get("created_at"),
                "transition_scope_ready_at": (metrics.get("onboarding_transition_scope_ready") or {}).get("created_at"),
                "first_value_ready_at": (metrics.get("onboarding_first_value_ready") or {}).get("created_at"),
                "canary_enabled_at": (metrics.get("onboarding_canary_enabled") or {}).get("created_at"),
                "time_to_first_value_seconds": int(time_to_first_value.get("metric_value") or 0)
                if time_to_first_value
                else None,
                "time_to_canary_seconds": int(time_to_canary.get("metric_value") or 0) if time_to_canary else None,
                "hesitation_seconds": hesitation_seconds,
                "hesitation_band": _hesitation_band(hesitation_seconds),
                "canary_enabled": canary_enabled,
                "first_value_ready": first_value_ready,
                "cohort": _cohort(
                    first_value_ready=first_value_ready,
                    canary_enabled=canary_enabled,
                    hesitation_seconds=hesitation_seconds,
                ),
                "starter_pack": str(snapshot_metadata.get("starter_pack") or "") or None,
                "total_transitions": total_transitions,
                "snapshot_confidence": _confidence_signal(total_transitions),
                "zero_transition_guard_hits": int(
                    event_counts[resolved_tenant].get("onboarding_zero_transition_guard_triggered") or 0
                ),
                "rollback_count": int(
                    event_counts[resolved_tenant].get("onboarding_protection_rolled_back") or 0
                ),
            }
        )

    sessions.sort(
        key=lambda item: (
            str(item.get("canary_enabled_at") or item.get("first_value_ready_at") or item.get("jira_connected_at") or ""),
            str(item.get("tenant_id") or ""),
        ),
        reverse=True,
    )

    connected_count = sum(1 for item in sessions if item.get("jira_connected_at"))
    first_value_count = sum(1 for item in sessions if item.get("first_value_ready"))
    canary_enabled_count = sum(1 for item in sessions if item.get("canary_enabled"))
    activation_drop_off_count = max(0, first_value_count - canary_enabled_count)
    hesitation_band_counts = Counter(
        str(item.get("hesitation_band"))
        for item in sessions
        if item.get("hesitation_band")
    )
    cohort_counts = Counter(str(item.get("cohort") or "unknown") for item in sessions)
    median_time_to_first_value = _median(
        item["time_to_first_value_seconds"]
        for item in sessions
        if item.get("time_to_first_value_seconds") is not None
    )
    median_time_to_canary = _median(
        item["time_to_canary_seconds"]
        for item in sessions
        if item.get("time_to_canary_seconds") is not None
    )
    median_hesitation = _median(
        item["hesitation_seconds"]
        for item in sessions
        if item.get("hesitation_seconds") is not None
    )
    onboarding_completion_rate = _ratio(first_value_count, connected_count)
    canary_conversion_rate = _ratio(canary_enabled_count, first_value_count)
    activation_drop_off_rate = _ratio(activation_drop_off_count, first_value_count)
    sample_size_ready = connected_count >= 5
    onboarding_completion_gte_80_pct = _pct_at_least(first_value_count, connected_count, 80)
    activation_drop_off_lt_20_pct = _pct_below(activation_drop_off_count, first_value_count, 20)
    median_hesitation_lt_5_seconds = median_hesitation is not None and median_hesitation < 5.0
    official_exit_criteria_met = all(
        (
            sample_size_ready,
            median_time_to_first_value is not None and median_time_to_first_value < 600.0,
            median_time_to_canary is not None and median_time_to_canary < 900.0,
            onboarding_completion_gte_80_pct,
            activation_drop_off_lt_20_pct,
        )
    )

    return {
        "window_days": int(days),
        "tenant_filter": {
            "tenant_id": str(tenant_id or "") or None,
            "tenant_prefix": str(tenant_prefix or "") or None,
        },
        "sessions_count": len(sessions),
        "connected_count": connected_count,
        "first_value_count": first_value_count,
        "canary_enabled_count": canary_enabled_count,
        "onboarding_completion_rate": onboarding_completion_rate,
        "canary_conversion_rate": canary_conversion_rate,
        "activation_drop_off_rate": activation_drop_off_rate,
        "median_time_to_first_value_seconds": median_time_to_first_value,
        "median_time_to_canary_seconds": median_time_to_canary,
        "median_hesitation_seconds": median_hesitation,
        "hesitation_bands": {
            "instant_trust": int(hesitation_band_counts.get("instant_trust") or 0),
            "acceptable_thinking": int(hesitation_band_counts.get("acceptable_thinking") or 0),
            "hesitation_or_doubt": int(hesitation_band_counts.get("hesitation_or_doubt") or 0),
        },
        "cohorts": dict(sorted(cohort_counts.items(), key=lambda item: item[0])),
        "exit_criteria": {
            "sample_size_ready": sample_size_ready,
            "first_value_under_10_minutes": median_time_to_first_value is not None
            and median_time_to_first_value < 600.0,
            "canary_under_15_minutes": median_time_to_canary is not None and median_time_to_canary < 900.0,
            "onboarding_completion_gte_80_pct": onboarding_completion_gte_80_pct,
            "activation_drop_off_lt_20_pct": activation_drop_off_lt_20_pct,
            "median_hesitation_lt_5_seconds": median_hesitation_lt_5_seconds,
            "official_phase1_proven": official_exit_criteria_met,
        },
        "sessions": sessions[: int(limit)],
    }
