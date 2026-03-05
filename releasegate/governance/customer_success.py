from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


DEFAULT_WINDOW_DAYS = 30
MAX_WINDOW_DAYS = 180
DEFAULT_TOP_USERS_LIMIT = 10
DEFAULT_REGRESSION_WINDOW_HOURS = 48
DEFAULT_REGRESSION_DROP_THRESHOLD = 10.0
BLOCKED_STATUSES = {"BLOCKED", "ERROR", "DENIED"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_window_days(window_days: int) -> int:
    parsed = int(window_days or DEFAULT_WINDOW_DAYS)
    if parsed < 1 or parsed > MAX_WINDOW_DAYS:
        raise ValueError(f"window_days must be between 1 and {MAX_WINDOW_DAYS}")
    return parsed


def _parse_required_datetime(value: str, *, field_name: str) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp")
    candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_window(
    *,
    from_ts: Optional[str],
    to_ts: Optional[str],
    window_days: int,
) -> Tuple[datetime, datetime]:
    now = _utc_now()
    bounded_window = _normalize_window_days(window_days)
    from_dt = _parse_required_datetime(from_ts, field_name="from") if str(from_ts or "").strip() else None
    to_dt = _parse_required_datetime(to_ts, field_name="to") if str(to_ts or "").strip() else None

    if from_dt is None and to_dt is None:
        to_dt = now
        from_dt = to_dt - timedelta(days=bounded_window)
    elif from_dt is None and to_dt is not None:
        from_dt = to_dt - timedelta(days=bounded_window)
    elif from_dt is not None and to_dt is None:
        to_dt = now

    if from_dt is None or to_dt is None:
        raise ValueError("invalid window")
    if from_dt > to_dt:
        raise ValueError("from must be before to")
    return from_dt, to_dt


def _parse_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _request_from_decision_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = payload.get("input_snapshot")
    if isinstance(snapshot, dict):
        request = snapshot.get("request")
        if isinstance(request, dict):
            return request
    return {}


def _risk_meta_from_decision_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = payload.get("input_snapshot")
    if isinstance(snapshot, dict):
        risk_meta = snapshot.get("risk_meta")
        if isinstance(risk_meta, dict):
            return risk_meta
    return {}


def _safe_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    raw = str(value or "").strip()
    if not raw:
        return float(default)
    try:
        return float(raw)
    except ValueError:
        return float(default)


def _parse_iso_datetime(value: Any) -> datetime:
    raw = str(value or "").strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    if raw:
        try:
            parsed = datetime.fromisoformat(raw)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return _utc_now()


def _decision_risk_score(payload: Dict[str, Any]) -> Optional[float]:
    risk_meta = _risk_meta_from_decision_payload(payload)
    if "risk_score" in risk_meta:
        return _safe_float(risk_meta.get("risk_score"))
    signal_map = payload.get("signal_map")
    if isinstance(signal_map, dict):
        risk = signal_map.get("risk")
        if isinstance(risk, dict) and "score" in risk:
            return _safe_float(risk.get("score"))
    return None


def _decision_actor(payload: Dict[str, Any], row: Dict[str, Any]) -> str:
    request = _request_from_decision_payload(payload)
    actor = (
        row.get("actor")
        or row.get("requested_by")
        or row.get("approved_by")
        or request.get("actor_account_id")
        or request.get("actor_id")
        or "unknown"
    )
    normalized = str(actor or "").strip()
    return normalized or "unknown"


def _iso_day(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).date().isoformat()


def _series_delta(series: List[Dict[str, Any]], *, key: str = "value") -> float:
    if len(series) < 2:
        return 0.0
    first = _safe_float(series[0].get(key))
    last = _safe_float(series[-1].get(key))
    return round(last - first, 6)


def get_customer_success_risk_trend(
    *,
    tenant_id: str,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    from_dt, to_dt = _parse_window(from_ts=from_ts, to_ts=to_ts, window_days=window_days)

    decision_rows = storage.fetchall(
        """
        SELECT decision_id, created_at, release_status, full_decision_json
        FROM audit_decisions
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
        ORDER BY created_at ASC
        """,
        (effective_tenant, from_dt.isoformat(), to_dt.isoformat()),
    )
    override_rows = storage.fetchall(
        """
        SELECT created_at
        FROM audit_overrides
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
        ORDER BY created_at ASC
        """,
        (effective_tenant, from_dt.isoformat(), to_dt.isoformat()),
    )

    daily: Dict[str, Dict[str, float]] = {}
    for row in decision_rows:
        created_at_dt = _parse_iso_datetime(row.get("created_at"))
        day = _iso_day(created_at_dt)
        bucket = daily.setdefault(
            day,
            {
                "risk_total": 0.0,
                "risk_count": 0.0,
                "decision_count": 0.0,
                "blocked_count": 0.0,
                "override_count": 0.0,
            },
        )
        bucket["decision_count"] += 1.0
        if str(row.get("release_status") or "").strip().upper() in BLOCKED_STATUSES:
            bucket["blocked_count"] += 1.0
        payload = _parse_json(row.get("full_decision_json"))
        risk_score = _decision_risk_score(payload)
        if risk_score is not None:
            bucket["risk_total"] += float(risk_score)
            bucket["risk_count"] += 1.0

    for row in override_rows:
        created_at_dt = _parse_iso_datetime(row.get("created_at"))
        day = _iso_day(created_at_dt)
        bucket = daily.setdefault(
            day,
            {
                "risk_total": 0.0,
                "risk_count": 0.0,
                "decision_count": 0.0,
                "blocked_count": 0.0,
                "override_count": 0.0,
            },
        )
        bucket["override_count"] += 1.0

    risk_series: List[Dict[str, Any]] = []
    stability_series: List[Dict[str, Any]] = []
    for day in sorted(daily):
        bucket = daily[day]
        risk_value = float(bucket["risk_total"]) / float(bucket["risk_count"]) if bucket["risk_count"] > 0 else 0.0
        decision_count = int(bucket["decision_count"])
        blocked_count = int(bucket["blocked_count"])
        override_count = int(bucket["override_count"])
        block_rate = (float(blocked_count) / float(decision_count)) if decision_count > 0 else 0.0
        override_rate = (float(override_count) / float(decision_count)) if decision_count > 0 else 0.0
        stability = max(0.0, 1.0 - (block_rate + override_rate))
        risk_series.append(
            {
                "t": day,
                "value": round(risk_value, 6),
                "decision_count": decision_count,
            }
        )
        stability_series.append(
            {
                "t": day,
                "value": round(stability, 6),
                "block_rate": round(block_rate, 6),
                "override_rate": round(override_rate, 6),
                "blocked_count": blocked_count,
                "override_count": override_count,
                "decision_count": decision_count,
            }
        )

    risk_delta = _series_delta(risk_series)
    stability_delta = _series_delta(stability_series)
    return {
        "tenant_id": effective_tenant,
        "from": from_dt.isoformat(),
        "to": to_dt.isoformat(),
        "window_days": _normalize_window_days(window_days),
        "risk_index": risk_series,
        "risk_delta_30d": risk_delta,
        "org_risk_reduction": round(-risk_delta, 6),
        "release_stability": stability_series,
        "release_stability_delta": stability_delta,
    }


def get_customer_success_override_analysis(
    *,
    tenant_id: str,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    top_users_limit: int = DEFAULT_TOP_USERS_LIMIT,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    from_dt, to_dt = _parse_window(from_ts=from_ts, to_ts=to_ts, window_days=window_days)
    bounded_top_users = max(1, min(int(top_users_limit or DEFAULT_TOP_USERS_LIMIT), 50))

    rows = storage.fetchall(
        """
        SELECT o.override_id, o.actor, o.requested_by, o.approved_by, o.created_at, d.full_decision_json
        FROM audit_overrides o
        LEFT JOIN audit_decisions d
          ON d.tenant_id = o.tenant_id
         AND d.decision_id = o.decision_id
        WHERE o.tenant_id = ?
          AND o.created_at >= ?
          AND o.created_at <= ?
        ORDER BY o.created_at ASC
        """,
        (effective_tenant, from_dt.isoformat(), to_dt.isoformat()),
    )

    actor_counts: Dict[str, int] = {}
    actor_last_seen: Dict[str, str] = {}
    total_overrides = 0
    midpoint = from_dt + ((to_dt - from_dt) / 2)
    baseline_overrides = 0
    recent_overrides = 0

    for row in rows:
        total_overrides += 1
        payload = _parse_json(row.get("full_decision_json"))
        actor = _decision_actor(payload, row)
        actor_counts[actor] = actor_counts.get(actor, 0) + 1
        actor_last_seen[actor] = str(row.get("created_at") or "")
        created_at = _parse_iso_datetime(row.get("created_at"))
        if created_at <= midpoint:
            baseline_overrides += 1
        else:
            recent_overrides += 1

    decision_total = int(
        storage.fetchone(
            """
            SELECT COUNT(*) AS value
            FROM audit_decisions
            WHERE tenant_id = ?
              AND created_at >= ?
              AND created_at <= ?
            """,
            (effective_tenant, from_dt.isoformat(), to_dt.isoformat()),
        ).get("value")
        or 0
    )

    baseline_decisions = int(
        storage.fetchone(
            """
            SELECT COUNT(*) AS value
            FROM audit_decisions
            WHERE tenant_id = ?
              AND created_at >= ?
              AND created_at <= ?
            """,
            (effective_tenant, from_dt.isoformat(), midpoint.isoformat()),
        ).get("value")
        or 0
    )
    recent_decisions = int(
        storage.fetchone(
            """
            SELECT COUNT(*) AS value
            FROM audit_decisions
            WHERE tenant_id = ?
              AND created_at > ?
              AND created_at <= ?
            """,
            (effective_tenant, midpoint.isoformat(), to_dt.isoformat()),
        ).get("value")
        or 0
    )

    top_users = sorted(actor_counts.items(), key=lambda item: (-item[1], item[0]))[:bounded_top_users]
    top_users_payload = [
        {
            "user": user,
            "overrides": int(count),
            "share": round((float(count) / float(total_overrides)) if total_overrides > 0 else 0.0, 6),
            "last_override_at": actor_last_seen.get(user),
        }
        for user, count in top_users
    ]

    top_3_count = sum(count for _, count in sorted(actor_counts.items(), key=lambda item: (-item[1], item[0]))[:3])
    concentration = (float(top_3_count) / float(total_overrides)) if total_overrides > 0 else 0.0
    baseline_rate = (float(baseline_overrides) / float(baseline_decisions)) if baseline_decisions > 0 else 0.0
    recent_rate = (float(recent_overrides) / float(recent_decisions)) if recent_decisions > 0 else 0.0
    weakening_signal = recent_rate >= max(0.05, baseline_rate * 1.2)

    return {
        "tenant_id": effective_tenant,
        "from": from_dt.isoformat(),
        "to": to_dt.isoformat(),
        "window_days": _normalize_window_days(window_days),
        "total_overrides": int(total_overrides),
        "total_decisions": int(decision_total),
        "top_users": top_users_payload,
        "override_concentration_index": round(concentration, 6),
        "policy_weakening_signal": bool(weakening_signal),
        "override_rate_baseline": round(baseline_rate, 6),
        "override_rate_recent": round(recent_rate, 6),
    }


def get_customer_success_regression_report(
    *,
    tenant_id: str,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    correlation_window_hours: int = DEFAULT_REGRESSION_WINDOW_HOURS,
    drop_threshold: float = DEFAULT_REGRESSION_DROP_THRESHOLD,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    from_dt, to_dt = _parse_window(from_ts=from_ts, to_ts=to_ts, window_days=window_days)
    bounded_window_hours = max(1, min(int(correlation_window_hours or DEFAULT_REGRESSION_WINDOW_HOURS), 168))
    threshold_drop = max(0.0, float(drop_threshold or DEFAULT_REGRESSION_DROP_THRESHOLD))

    event_rows = storage.fetchall(
        """
        SELECT event_id, policy_id, event_type, metadata_json, created_at
        FROM policy_registry_events
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
          AND event_type IN ('POLICY_ACTIVATED', 'POLICY_ROLLBACK')
        ORDER BY created_at DESC
        """,
        (effective_tenant, from_dt.isoformat(), to_dt.isoformat()),
    )

    regressions: List[Dict[str, Any]] = []
    for row in event_rows:
        changed_at = _parse_iso_datetime(row.get("created_at"))
        pre_start = changed_at - timedelta(hours=bounded_window_hours)
        post_end = changed_at + timedelta(hours=bounded_window_hours)

        before_row = storage.fetchone(
            """
            SELECT AVG(integrity_score) AS avg_integrity
            FROM governance_daily_metrics
            WHERE tenant_id = ?
              AND date_utc >= ?
              AND date_utc < ?
            """,
            (
                effective_tenant,
                pre_start.date().isoformat(),
                changed_at.date().isoformat(),
            ),
        )
        after_row = storage.fetchone(
            """
            SELECT AVG(integrity_score) AS avg_integrity
            FROM governance_daily_metrics
            WHERE tenant_id = ?
              AND date_utc > ?
              AND date_utc <= ?
            """,
            (
                effective_tenant,
                changed_at.date().isoformat(),
                post_end.date().isoformat(),
            ),
        )
        integrity_before = _safe_float((before_row or {}).get("avg_integrity"))
        integrity_after = _safe_float((after_row or {}).get("avg_integrity"))
        integrity_drop = round(integrity_before - integrity_after, 6)
        if integrity_drop < threshold_drop:
            continue
        metadata = _parse_json(row.get("metadata_json"))
        scope_type = str(metadata.get("scope_type") or "").strip().lower()
        scope_id = str(metadata.get("scope_id") or "").strip()
        affected_workflows: List[str]
        if scope_type == "workflow" and scope_id:
            affected_workflows = [scope_id]
        else:
            affected_workflows = ["unknown"]
        regressions.append(
            {
                "policy_change_id": str(row.get("event_id") or ""),
                "policy_id": str(row.get("policy_id") or ""),
                "event_type": str(row.get("event_type") or ""),
                "changed_at": changed_at.isoformat(),
                "integrity_before": round(integrity_before, 6),
                "integrity_after": round(integrity_after, 6),
                "integrity_drop": integrity_drop,
                "integrity_drop_ratio": round((integrity_drop / integrity_before), 6) if integrity_before > 0 else 0.0,
                "correlation_window_hours": bounded_window_hours,
                "affected_workflows": affected_workflows,
                "policy_diff_path": "/policies/diff",
                "decisions_path": "/observability?metric=block_frequency",
            }
        )

    return {
        "tenant_id": effective_tenant,
        "from": from_dt.isoformat(),
        "to": to_dt.isoformat(),
        "window_days": _normalize_window_days(window_days),
        "threshold_drop": round(threshold_drop, 6),
        "total_policy_changes": len(event_rows),
        "regressions_detected": len(regressions),
        "regressions": regressions,
    }
