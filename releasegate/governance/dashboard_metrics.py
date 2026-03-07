from __future__ import annotations

import json
import os
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import date, datetime, timedelta, timezone
from time import perf_counter
from typing import Any, Dict, List, Optional, Tuple

from releasegate.governance.integrity import get_tenant_governance_integrity
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id


DEFAULT_WINDOW_DAYS = 30
MAX_WINDOW_DAYS = 90
DEFAULT_BLOCKED_LIMIT = 25
MAX_BLOCKED_LIMIT = 100
DEFAULT_OVERRIDES_GROUP_BY = "actor"
DEFAULT_OVERRIDES_LIMIT = 25
MAX_OVERRIDES_LIMIT = 100
SAMPLE_OVERRIDE_IDS_LIMIT = 3
DEFAULT_TIMESERIES_BUCKET = "day"
DEFAULT_DRILLDOWN_LIMIT = 50
MAX_DRILLDOWN_LIMIT = 200
ALERT_BASELINE_DAYS = 7
OVERRIDE_SPIKE_MULTIPLIER = 2.0
DRIFT_SPIKE_MULTIPLIER = 2.0
OVERRIDE_SPIKE_MIN_RATE = 0.05
DRIFT_SPIKE_MIN_INDEX = 0.02
BLOCKED_STATUSES = {"BLOCKED", "ERROR", "DENIED"}

TIMESERIES_METRICS: Dict[str, Dict[str, Any]] = {
    "integrity_score": {
        "display_name": "Integrity Score",
        "unit": "score",
        "higher_is_better": True,
        "description": "Governance integrity score from daily rollups.",
    },
    "drift_index": {
        "display_name": "Drift Index",
        "unit": "ratio",
        "higher_is_better": False,
        "description": "Policy/behavior drift signal from governance rollups.",
    },
    "override_rate": {
        "display_name": "Override Rate",
        "unit": "ratio",
        "higher_is_better": False,
        "description": "Overrides divided by total decisions in the selected bucket.",
    },
    "block_frequency": {
        "display_name": "Block Frequency",
        "unit": "ratio",
        "higher_is_better": False,
        "description": "Blocked decisions divided by total decisions in the selected bucket.",
    },
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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


def _normalize_window_days(window_days: int) -> int:
    parsed = int(window_days or DEFAULT_WINDOW_DAYS)
    if parsed < 1 or parsed > MAX_WINDOW_DAYS:
        raise ValueError(f"window_days must be between 1 and {MAX_WINDOW_DAYS}")
    return parsed


def _normalize_limit(limit: int) -> int:
    parsed = int(limit or DEFAULT_BLOCKED_LIMIT)
    if parsed < 1 or parsed > MAX_BLOCKED_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_BLOCKED_LIMIT}")
    return parsed


def _normalize_overrides_group_by(group_by: str) -> str:
    normalized = str(group_by or DEFAULT_OVERRIDES_GROUP_BY).strip().lower()
    if normalized not in {"actor", "workflow", "rule"}:
        raise ValueError("group_by must be one of actor, workflow, rule")
    return normalized


def _normalize_overrides_limit(limit: int) -> int:
    parsed = int(limit or DEFAULT_OVERRIDES_LIMIT)
    if parsed < 1 or parsed > MAX_OVERRIDES_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_OVERRIDES_LIMIT}")
    return parsed


def _normalize_timeseries_metric(metric: str) -> str:
    normalized = str(metric or "").strip().lower()
    if normalized not in TIMESERIES_METRICS:
        supported = ", ".join(sorted(TIMESERIES_METRICS))
        raise ValueError(f"metric must be one of {supported}")
    return normalized


def _normalize_timeseries_bucket(bucket: str) -> str:
    normalized = str(bucket or DEFAULT_TIMESERIES_BUCKET).strip().lower()
    if normalized not in {"day", "hour"}:
        raise ValueError("bucket must be one of day, hour")
    return normalized


def _normalize_drilldown_limit(limit: int) -> int:
    parsed = int(limit or DEFAULT_DRILLDOWN_LIMIT)
    if parsed < 1 or parsed > MAX_DRILLDOWN_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_DRILLDOWN_LIMIT}")
    return parsed


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


def _iso_date(value: Any) -> str:
    raw = str(value or "").strip()
    if raw:
        return raw[:10]
    return _utc_now().date().isoformat()


def _iso_datetime_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    candidate = raw
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _coerce_date_utc(value: date | datetime | str) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        dt = value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.date()
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("date_utc is required")
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    if "T" in raw:
        try:
            dt = datetime.fromisoformat(raw)
            dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            return dt.date()
        except ValueError as exc:
            raise ValueError("date_utc must be an ISO-8601 date or timestamp") from exc
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError("date_utc must be an ISO-8601 date") from exc


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


def _parse_override_window(
    *,
    from_ts: Optional[str],
    to_ts: Optional[str],
) -> Tuple[datetime, datetime]:
    now = _utc_now()
    from_dt = _parse_required_datetime(from_ts, field_name="from") if str(from_ts or "").strip() else None
    to_dt = _parse_required_datetime(to_ts, field_name="to") if str(to_ts or "").strip() else None

    if from_dt is None and to_dt is None:
        to_dt = now
        from_dt = to_dt - timedelta(days=DEFAULT_WINDOW_DAYS)
    elif from_dt is None and to_dt is not None:
        from_dt = to_dt - timedelta(days=DEFAULT_WINDOW_DAYS)
    elif from_dt is not None and to_dt is None:
        to_dt = now

    if from_dt is None or to_dt is None:
        raise ValueError("invalid override window")
    if from_dt > to_dt:
        raise ValueError("from must be before to")
    return from_dt, to_dt


def _parse_metrics_window(
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
        raise ValueError("invalid metrics window")
    if from_dt > to_dt:
        raise ValueError("from must be before to")
    return from_dt, to_dt


def _override_rate_from_counts(*, override_count: int, decision_count: int) -> float:
    if int(decision_count or 0) <= 0:
        return 0.0
    return float(override_count) / float(decision_count)


def _block_frequency_from_counts(*, blocked_count: int, decision_count: int) -> float:
    if int(decision_count or 0) <= 0:
        return 0.0
    return float(blocked_count) / float(decision_count)


def _extract_drift_breakdown(details_json: Any) -> Optional[Dict[str, Any]]:
    details = _parse_json(details_json)
    if not details:
        return None
    if isinstance(details.get("policy_drift"), dict):
        return details.get("policy_drift")
    if isinstance(details.get("drift_breakdown"), dict):
        return details.get("drift_breakdown")
    return None


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


def _severity_rank(value: str) -> int:
    normalized = str(value or "").strip().lower()
    if normalized == "high":
        return 0
    if normalized == "medium":
        return 1
    return 2


def _rollup_override_abuse(
    *,
    override_count: int,
    decision_count: int,
    metrics: Dict[str, Any],
) -> Dict[str, Any]:
    override_meta = metrics.get("override_abuse") if isinstance(metrics.get("override_abuse"), dict) else {}
    override_rate = _override_rate_from_counts(
        override_count=override_count,
        decision_count=decision_count,
    )
    top_actor_share = _safe_float(override_meta.get("top_actor_share"))
    if top_actor_share <= 0.0 and override_count > 0:
        top_actor_share = 1.0
    actor_concentration = min(1.0, max(0.0, top_actor_share))
    top_actor_override_count = int(round(float(override_count) * actor_concentration)) if override_count > 0 else 0
    override_abuse_index = override_rate * actor_concentration
    return {
        "override_abuse_index": round(override_abuse_index, 6),
        "override_abuse": {
            "override_rate": round(override_rate, 6),
            "override_count": int(override_count),
            "decision_count": int(decision_count),
            "top_actor_override_count": int(top_actor_override_count),
            "actor_concentration": round(actor_concentration, 6),
        },
    }


def _fetch_prior_rollup_rows(
    *,
    tenant_id: str,
    day: date,
    limit: int = ALERT_BASELINE_DAYS,
) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    return storage.fetchall(
        """
        SELECT
            date_utc,
            override_rate,
            drift_index,
            strict_mode_count,
            decision_count
        FROM governance_daily_metrics
        WHERE tenant_id = ?
          AND date_utc < ?
        ORDER BY date_utc DESC
        LIMIT ?
        """,
        (tenant_id, day.isoformat(), int(limit)),
    )


def _mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values)) / float(len(values))


def _build_daily_alerts(
    *,
    tenant_id: str,
    day: date,
    override_rate: float,
    drift_index: float,
    strict_mode_count: int,
    decision_count: int,
    override_count: int,
    prior_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    recent = list(prior_rows[:ALERT_BASELINE_DAYS])
    baseline_override = _mean([_safe_float(row.get("override_rate")) for row in recent])
    baseline_drift = _mean([_safe_float(row.get("drift_index")) for row in recent])
    alerts: List[Dict[str, Any]] = []

    if (
        baseline_override > 0.0
        and override_rate > max(OVERRIDE_SPIKE_MIN_RATE, baseline_override * OVERRIDE_SPIKE_MULTIPLIER)
    ):
        alerts.append(
            {
                "date_utc": day.isoformat(),
                "severity": "high",
                "code": "OVERRIDE_SPIKE",
                "title": "Override rate spiked vs 7-day baseline",
                "details": {
                    "today": round(override_rate, 6),
                    "baseline_7d": round(baseline_override, 6),
                    "override_count": int(override_count),
                    "decision_count": int(decision_count),
                },
            }
        )

    if (
        baseline_drift > 0.0
        and drift_index > max(DRIFT_SPIKE_MIN_INDEX, baseline_drift * DRIFT_SPIKE_MULTIPLIER)
    ):
        alerts.append(
            {
                "date_utc": day.isoformat(),
                "severity": "medium",
                "code": "DRIFT_SPIKE",
                "title": "Drift index spiked vs 7-day baseline",
                "details": {
                    "today": round(drift_index, 6),
                    "baseline_7d": round(baseline_drift, 6),
                },
            }
        )

    yesterday = day - timedelta(days=1)
    yesterday_row = next(
        (
            row
            for row in recent
            if _iso_date(row.get("date_utc")) == yesterday.isoformat()
        ),
        None,
    )
    if yesterday_row is not None:
        yesterday_strict = int(yesterday_row.get("strict_mode_count") or 0)
        if strict_mode_count < yesterday_strict:
            alerts.append(
                {
                    "date_utc": day.isoformat(),
                    "severity": "high",
                    "code": "STRICT_MODE_DROP",
                    "title": "Strict mode count dropped from previous day",
                    "details": {
                        "today": int(strict_mode_count),
                        "yesterday": int(yesterday_strict),
                    },
                }
            )

    if decision_count == 0:
        alerts.append(
            {
                "date_utc": day.isoformat(),
                "severity": "medium",
                "code": "NO_DATA",
                "title": "No decisions recorded for this rollup window",
                "details": {"decision_count": 0},
            }
        )

    return sorted(
        alerts,
        key=lambda alert: (
            -int(_iso_date(alert.get("date_utc")).replace("-", "")),
            _severity_rank(str(alert.get("severity") or "medium")),
            str(alert.get("code") or ""),
        ),
    )


def _collect_alert_counts(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        severity = str(alert.get("severity") or "").strip().lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _extract_policy_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    bindings = payload.get("policy_bindings")
    if isinstance(bindings, list):
        for item in bindings:
            if isinstance(item, dict):
                return item
    return {}


def _derive_override_actor(row: Dict[str, Any]) -> str:
    for key in ("actor", "requested_by", "approved_by"):
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return "unknown"


def _derive_override_workflow_key(row: Dict[str, Any], payload: Dict[str, Any], request: Dict[str, Any]) -> str:
    overrides = request.get("context_overrides") if isinstance(request.get("context_overrides"), dict) else {}
    for value in (
        overrides.get("workflow_id"),
        request.get("workflow_id"),
        row.get("transition_id"),
        request.get("transition_id"),
        row.get("target_id") if str(row.get("target_type") or "").strip() == "transition" else None,
    ):
        candidate = str(value or "").strip()
        if candidate:
            return candidate
    return "unknown"


def _derive_override_rule_key(row: Dict[str, Any], payload: Dict[str, Any]) -> str:
    binding = _extract_policy_binding(payload)
    policy_id = str(binding.get("policy_id") or row.get("policy_id") or "").strip()
    policy_version = str(binding.get("policy_version") or row.get("policy_version") or "").strip()
    if policy_id and policy_version:
        return f"{policy_id}:{policy_version}"
    if policy_id:
        return policy_id
    policy_hash = str(binding.get("policy_hash") or row.get("policy_hash") or "").strip()
    if policy_hash:
        return policy_hash
    reason_code = str(payload.get("reason_code") or "").strip()
    if reason_code:
        return f"reason:{reason_code}"
    return "unknown"


def get_dashboard_overrides_breakdown(
    *,
    tenant_id: str,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    group_by: str = DEFAULT_OVERRIDES_GROUP_BY,
    limit: int = DEFAULT_OVERRIDES_LIMIT,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_group_by = _normalize_overrides_group_by(group_by)
    bounded_limit = _normalize_overrides_limit(limit)
    from_dt, to_dt = _parse_override_window(from_ts=from_ts, to_ts=to_ts)

    rows = storage.fetchall(
        """
        SELECT
            o.override_id,
            o.decision_id,
            o.actor,
            o.requested_by,
            o.approved_by,
            o.target_type,
            o.target_id,
            o.created_at,
            d.full_decision_json,
            d.policy_hash AS decision_policy_hash,
            l.transition_id AS link_transition_id,
            l.policy_id AS link_policy_id,
            l.policy_version AS link_policy_version,
            l.policy_hash AS link_policy_hash
        FROM audit_overrides o
        LEFT JOIN audit_decisions d
          ON d.tenant_id = o.tenant_id
         AND d.decision_id = o.decision_id
        LEFT JOIN decision_transition_links l
          ON l.tenant_id = o.tenant_id
         AND l.decision_id = o.decision_id
        WHERE o.tenant_id = ?
          AND o.created_at >= ?
          AND o.created_at <= ?
        ORDER BY o.created_at DESC, o.override_id ASC
        """,
        (
            effective_tenant,
            from_dt.isoformat(),
            to_dt.isoformat(),
        ),
    )

    buckets: Dict[str, Dict[str, Any]] = {}
    total_overrides = 0
    for row in rows:
        override_id = str(row.get("override_id") or "").strip()
        if not override_id:
            continue
        total_overrides += 1

        payload = _parse_json(row.get("full_decision_json"))
        request = _request_from_decision_payload(payload)
        enriched_row = dict(row)
        enriched_row["transition_id"] = str(row.get("link_transition_id") or "").strip()
        enriched_row["policy_id"] = str(row.get("link_policy_id") or "").strip()
        enriched_row["policy_version"] = str(row.get("link_policy_version") or "").strip()
        enriched_row["policy_hash"] = (
            str(row.get("link_policy_hash") or "").strip()
            or str(row.get("decision_policy_hash") or "").strip()
        )

        actor_key = _derive_override_actor(enriched_row)
        workflow_key = _derive_override_workflow_key(enriched_row, payload, request)
        rule_key = _derive_override_rule_key(enriched_row, payload)
        if normalized_group_by == "actor":
            aggregate_key = actor_key
        elif normalized_group_by == "workflow":
            aggregate_key = workflow_key
        else:
            aggregate_key = rule_key

        created_at_iso = _iso_datetime_or_none(row.get("created_at")) or str(row.get("created_at") or "").strip()
        created_at_dt = _parse_iso_datetime(created_at_iso)

        bucket = buckets.setdefault(
            aggregate_key,
            {
                "key": aggregate_key,
                "count": 0,
                "workflows": set(),
                "rules": set(),
                "actors": set(),
                "last_seen": None,
                "last_seen_dt": None,
                "sample_override_ids": [],
            },
        )
        bucket["count"] += 1
        bucket["workflows"].add(workflow_key)
        bucket["rules"].add(rule_key)
        bucket["actors"].add(actor_key)
        if len(bucket["sample_override_ids"]) < SAMPLE_OVERRIDE_IDS_LIMIT:
            bucket["sample_override_ids"].append(override_id)
        if bucket["last_seen_dt"] is None or created_at_dt > bucket["last_seen_dt"]:
            bucket["last_seen_dt"] = created_at_dt
            bucket["last_seen"] = created_at_iso or created_at_dt.isoformat()

    normalized_rows: List[Dict[str, Any]] = []
    for bucket in buckets.values():
        normalized_rows.append(
            {
                "key": str(bucket.get("key") or "unknown"),
                "count": int(bucket.get("count") or 0),
                "workflows": len(bucket.get("workflows") or ()),
                "rules": len(bucket.get("rules") or ()),
                "actors": len(bucket.get("actors") or ()),
                "last_seen": str(bucket.get("last_seen") or ""),
                "sample_override_ids": list(bucket.get("sample_override_ids") or []),
            }
        )
    normalized_rows.sort(
        key=lambda item: (
            -int(item.get("count") or 0),
            str(item.get("key") or ""),
        ),
    )

    return {
        "tenant": effective_tenant,
        "from": from_dt.isoformat(),
        "to": to_dt.isoformat(),
        "group_by": normalized_group_by,
        "total_overrides": int(total_overrides),
        "rows": normalized_rows[:bounded_limit],
    }


def _encode_blocked_cursor(*, created_at: str, decision_id: str) -> str:
    payload = {
        "created_at": str(created_at or ""),
        "decision_id": str(decision_id or ""),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    return urlsafe_b64encode(raw).decode("ascii")


def _decode_blocked_cursor(cursor: Optional[str]) -> Optional[Tuple[str, str]]:
    raw_cursor = str(cursor or "").strip()
    if not raw_cursor:
        return None
    try:
        decoded = urlsafe_b64decode(raw_cursor.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
    except Exception as exc:
        raise ValueError("cursor is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("cursor is invalid")
    created_at = str(payload.get("created_at") or "").strip()
    decision_id = str(payload.get("decision_id") or "").strip()
    if not created_at or not decision_id:
        raise ValueError("cursor is invalid")
    return created_at, decision_id


def _bucket_start(dt: datetime, *, bucket: str) -> str:
    if bucket == "hour":
        return dt.replace(minute=0, second=0, microsecond=0).isoformat()
    return datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc).isoformat()


def _timeseries_value_from_row(*, metric: str, row: Dict[str, Any]) -> Tuple[float, Optional[int], Optional[int]]:
    decision_count = int(row.get("decision_count") or 0)
    override_count = int(row.get("override_count") or 0)
    blocked_count = int(row.get("blocked_count") or 0)
    if metric == "integrity_score":
        return float(row.get("integrity_score") or 0.0), None, None
    if metric == "drift_index":
        return float(row.get("drift_index") or 0.0), None, None
    if metric == "override_rate":
        return _override_rate_from_counts(override_count=override_count, decision_count=decision_count), override_count, decision_count
    return _block_frequency_from_counts(blocked_count=blocked_count, decision_count=decision_count), blocked_count, decision_count


def _decision_item_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = _parse_json(row.get("full_decision_json"))
    request = _request_from_decision_payload(payload)
    overrides = request.get("context_overrides") if isinstance(request.get("context_overrides"), dict) else {}
    workflow_id = str(
        overrides.get("workflow_id")
        or request.get("workflow_id")
        or request.get("transition_name")
        or ""
    )
    decision_id = str(row.get("decision_id") or "")
    return {
        "decision_id": decision_id,
        "created_at": str(row.get("created_at") or ""),
        "decision_status": str(row.get("release_status") or ""),
        "reason_code": str(payload.get("reason_code") or ""),
        "jira_issue_id": str(request.get("issue_key") or ""),
        "workflow_id": workflow_id,
        "transition_id": str(request.get("transition_id") or ""),
        "actor": str(request.get("actor_account_id") or request.get("actor_id") or ""),
        "environment": str(request.get("environment") or ""),
        "project_key": str(request.get("project_key") or ""),
        "policy_hash": str(row.get("policy_hash") or ""),
        "explainer_path": f"/dashboard/decisions/{decision_id}/explainer",
    }


def get_metrics_timeseries(
    *,
    tenant_id: str,
    metric: str,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    bucket: str = DEFAULT_TIMESERIES_BUCKET,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_metric = _normalize_timeseries_metric(metric)
    normalized_bucket = _normalize_timeseries_bucket(bucket)
    from_dt, to_dt = _parse_metrics_window(
        from_ts=from_ts,
        to_ts=to_ts,
        window_days=window_days,
    )

    if normalized_bucket == "hour" and normalized_metric in {"integrity_score", "drift_index"}:
        raise ValueError("hour bucket is only supported for override_rate and block_frequency")

    series: List[Dict[str, Any]] = []
    if normalized_bucket == "day":
        rows = storage.fetchall(
            """
            SELECT
                date_utc,
                integrity_score,
                drift_index,
                blocked_count,
                override_count,
                decision_count
            FROM governance_daily_metrics
            WHERE tenant_id = ?
              AND date_utc >= ?
              AND date_utc <= ?
            ORDER BY date_utc ASC
            """,
            (
                effective_tenant,
                from_dt.date().isoformat(),
                to_dt.date().isoformat(),
            ),
        )
        for row in rows:
            value, numerator, denominator = _timeseries_value_from_row(metric=normalized_metric, row=row)
            point: Dict[str, Any] = {
                "t": f"{_iso_date(row.get('date_utc'))}T00:00:00+00:00",
                "value": round(float(value), 6),
            }
            if numerator is not None:
                point["numerator"] = int(numerator)
            if denominator is not None:
                point["denominator"] = int(denominator)
            series.append(point)
    else:
        decision_rows = storage.fetchall(
            """
            SELECT created_at, release_status
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
        buckets: Dict[str, Dict[str, int]] = {}
        for row in decision_rows:
            bucket_key = _bucket_start(_parse_iso_datetime(row.get("created_at")), bucket=normalized_bucket)
            counts = buckets.setdefault(bucket_key, {"decision_count": 0, "blocked_count": 0, "override_count": 0})
            counts["decision_count"] += 1
            if str(row.get("release_status") or "").strip().upper() in BLOCKED_STATUSES:
                counts["blocked_count"] += 1
        for row in override_rows:
            bucket_key = _bucket_start(_parse_iso_datetime(row.get("created_at")), bucket=normalized_bucket)
            counts = buckets.setdefault(bucket_key, {"decision_count": 0, "blocked_count": 0, "override_count": 0})
            counts["override_count"] += 1

        for bucket_key in sorted(buckets):
            counts = buckets[bucket_key]
            if normalized_metric == "override_rate":
                value = _override_rate_from_counts(
                    override_count=int(counts.get("override_count") or 0),
                    decision_count=int(counts.get("decision_count") or 0),
                )
                numerator = int(counts.get("override_count") or 0)
            else:
                value = _block_frequency_from_counts(
                    blocked_count=int(counts.get("blocked_count") or 0),
                    decision_count=int(counts.get("decision_count") or 0),
                )
                numerator = int(counts.get("blocked_count") or 0)
            series.append(
                {
                    "t": bucket_key,
                    "value": round(float(value), 6),
                    "numerator": numerator,
                    "denominator": int(counts.get("decision_count") or 0),
                }
            )

    meta = TIMESERIES_METRICS[normalized_metric]
    return {
        "tenant_id": effective_tenant,
        "metric": normalized_metric,
        "display_name": str(meta.get("display_name") or normalized_metric),
        "unit": str(meta.get("unit") or "ratio"),
        "higher_is_better": bool(meta.get("higher_is_better")),
        "description": str(meta.get("description") or ""),
        "bucket": normalized_bucket,
        "from": from_dt.isoformat(),
        "to": to_dt.isoformat(),
        "series": series,
    }


def get_metrics_summary(
    *,
    tenant_id: str,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    from_dt, to_dt = _parse_metrics_window(
        from_ts=from_ts,
        to_ts=to_ts,
        window_days=window_days,
    )
    metrics: Dict[str, Dict[str, Any]] = {}
    for metric_name, metric_meta in TIMESERIES_METRICS.items():
        payload = get_metrics_timeseries(
            tenant_id=effective_tenant,
            metric=metric_name,
            from_ts=from_dt.isoformat(),
            to_ts=to_dt.isoformat(),
            window_days=window_days,
            bucket="day",
        )
        series = payload.get("series") if isinstance(payload.get("series"), list) else []
        latest_point = series[-1] if series else None
        previous_point = series[-2] if len(series) > 1 else None
        latest_value = float((latest_point or {}).get("value") or 0.0)
        previous_value = float(previous_point.get("value")) if isinstance(previous_point, dict) else None
        delta = latest_value - previous_value if previous_value is not None else None
        metrics[metric_name] = {
            "display_name": metric_meta.get("display_name"),
            "unit": metric_meta.get("unit"),
            "higher_is_better": bool(metric_meta.get("higher_is_better")),
            "value": round(latest_value, 6),
            "previous": round(previous_value, 6) if previous_value is not None else None,
            "delta": round(delta, 6) if delta is not None else None,
            "sample_size": len(series),
        }

    return {
        "tenant_id": effective_tenant,
        "from": from_dt.isoformat(),
        "to": to_dt.isoformat(),
        "window_days": _normalize_window_days(window_days),
        "metrics": metrics,
    }


def get_metrics_drilldown(
    *,
    tenant_id: str,
    metric: str,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    limit: int = DEFAULT_DRILLDOWN_LIMIT,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_metric = _normalize_timeseries_metric(metric)
    bounded_limit = _normalize_drilldown_limit(limit)
    from_dt, to_dt = _parse_metrics_window(
        from_ts=from_ts,
        to_ts=to_ts,
        window_days=window_days,
    )

    items: List[Dict[str, Any]] = []
    if normalized_metric == "override_rate":
        override_rows = storage.fetchall(
            """
            SELECT decision_id
            FROM audit_overrides
            WHERE tenant_id = ?
              AND created_at >= ?
              AND created_at <= ?
            ORDER BY created_at DESC, override_id ASC
            LIMIT ?
            """,
            (effective_tenant, from_dt.isoformat(), to_dt.isoformat(), bounded_limit * 4),
        )
        seen: set[str] = set()
        decision_ids: List[str] = []
        for row in override_rows:
            decision_id = str(row.get("decision_id") or "").strip()
            if not decision_id or decision_id in seen:
                continue
            seen.add(decision_id)
            decision_ids.append(decision_id)
            if len(decision_ids) >= bounded_limit:
                break
        for decision_id in decision_ids:
            row = storage.fetchone(
                """
                SELECT decision_id, created_at, release_status, full_decision_json, policy_hash
                FROM audit_decisions
                WHERE tenant_id = ? AND decision_id = ?
                LIMIT 1
                """,
                (effective_tenant, decision_id),
            )
            if row:
                items.append(_decision_item_from_row(row))
    else:
        filter_clause = ""
        params: List[Any] = [effective_tenant, from_dt.isoformat(), to_dt.isoformat()]
        if normalized_metric == "block_frequency":
            filter_clause = "AND release_status IN ('BLOCKED', 'ERROR', 'DENIED')"
        rows = storage.fetchall(
            f"""
            SELECT decision_id, created_at, release_status, full_decision_json, policy_hash
            FROM audit_decisions
            WHERE tenant_id = ?
              AND created_at >= ?
              AND created_at <= ?
              {filter_clause}
            ORDER BY created_at DESC
            LIMIT ?
            """,
            tuple(params + [bounded_limit * 4]),
        )
        for row in rows:
            item = _decision_item_from_row(row)
            if normalized_metric == "drift_index":
                reason_code = str(item.get("reason_code") or "").upper()
                if "DRIFT" not in reason_code and item.get("decision_status") == "ALLOWED":
                    continue
            elif normalized_metric == "integrity_score":
                status = str(item.get("decision_status") or "").upper()
                if status == "ALLOWED":
                    continue
            items.append(item)
            if len(items) >= bounded_limit:
                break

    return {
        "tenant_id": effective_tenant,
        "metric": normalized_metric,
        "from": from_dt.isoformat(),
        "to": to_dt.isoformat(),
        "limit": bounded_limit,
        "items": items[:bounded_limit],
    }


def list_integrity_trend(
    *,
    tenant_id: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_window = _normalize_window_days(window_days)
    start_date = (_utc_now().date() - timedelta(days=bounded_window - 1)).isoformat()
    rows = storage.fetchall(
        """
        SELECT
            date_utc,
            integrity_score,
            drift_index,
            override_rate,
            blocked_count,
            override_count,
            decision_count,
            details_json
        FROM governance_daily_metrics
        WHERE tenant_id = ? AND date_utc >= ?
        ORDER BY date_utc ASC
        """,
        (effective_tenant, start_date),
    )
    trend: List[Dict[str, Any]] = []
    for row in rows:
        details_json = _parse_json(row.get("details_json"))
        override_count = int(row.get("override_count") or 0)
        decision_count = int(row.get("decision_count") or 0)
        trend.append(
            {
                "date_utc": _iso_date(row.get("date_utc")),
                "integrity_score": float(row.get("integrity_score") or 0.0),
                "drift_index": float(row.get("drift_index") or 0.0),
                "override_rate": _override_rate_from_counts(
                    override_count=override_count,
                    decision_count=decision_count,
                ),
                "override_count": override_count,
                "decision_count": decision_count,
                "blocked_count": int(row.get("blocked_count") or 0),
                "drift_breakdown": _extract_drift_breakdown(details_json),
                "override_abuse_index": _safe_float(details_json.get("override_abuse_index")),
            }
        )
    return trend


def list_recent_blocked_decisions(
    *,
    tenant_id: str,
    limit: int = DEFAULT_BLOCKED_LIMIT,
) -> List[Dict[str, Any]]:
    page = list_recent_blocked_decisions_page(
        tenant_id=tenant_id,
        limit=limit,
        cursor=None,
    )
    return page.get("items") if isinstance(page.get("items"), list) else []


def list_recent_blocked_decisions_page(
    *,
    tenant_id: str,
    limit: int = DEFAULT_BLOCKED_LIMIT,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_limit = _normalize_limit(limit)
    decoded_cursor = _decode_blocked_cursor(cursor)
    params: List[Any] = [effective_tenant]
    cursor_clause = ""
    if decoded_cursor is not None:
        cursor_created_at, cursor_decision_id = decoded_cursor
        cursor_clause = "AND (created_at < ? OR (created_at = ? AND decision_id < ?))"
        params.extend([cursor_created_at, cursor_created_at, cursor_decision_id])
    params.append(bounded_limit + 1)
    rows = storage.fetchall(
        f"""
        SELECT decision_id, created_at, release_status, full_decision_json, policy_hash
        FROM audit_decisions
        WHERE tenant_id = ?
          AND release_status IN ('BLOCKED', 'ERROR', 'DENIED')
          {cursor_clause}
        ORDER BY created_at DESC
        LIMIT ?
        """,
        tuple(params),
    )

    items: List[Dict[str, Any]] = []
    for row in rows[:bounded_limit]:
        payload = _parse_json(row.get("full_decision_json"))
        request = _request_from_decision_payload(payload)
        overrides = request.get("context_overrides") if isinstance(request.get("context_overrides"), dict) else {}
        workflow_id = str(
            overrides.get("workflow_id")
            or request.get("workflow_id")
            or request.get("transition_name")
            or ""
        )
        items.append(
            {
                "decision_id": str(row.get("decision_id") or ""),
                "created_at": str(row.get("created_at") or ""),
                "decision_status": str(row.get("release_status") or ""),
                "reason_code": str(payload.get("reason_code") or ""),
                "jira_issue_id": str(request.get("issue_key") or ""),
                "workflow_id": workflow_id,
                "transition_id": str(request.get("transition_id") or ""),
                "workflow": workflow_id,
                "transition": str(request.get("transition_id") or ""),
                "actor": str(request.get("actor_account_id") or request.get("actor_id") or ""),
                "environment": str(request.get("environment") or ""),
                "project_key": str(request.get("project_key") or ""),
                "policy_hash": str(row.get("policy_hash") or ""),
                "subject_ref": str(request.get("issue_key") or ""),
                "explainer_path": f"/dashboard/decisions/{str(row.get('decision_id') or '')}/explainer",
            }
        )
    next_cursor: Optional[str] = None
    if len(rows) > bounded_limit and items:
        last_item = items[-1]
        next_cursor = _encode_blocked_cursor(
            created_at=str(last_item.get("created_at") or ""),
            decision_id=str(last_item.get("decision_id") or ""),
        )
    return {
        "items": items,
        "next_cursor": next_cursor,
    }


def list_active_strict_modes(*, tenant_id: str) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    active: List[Dict[str, Any]] = []

    policy_rows = storage.fetchall(
        """
        SELECT
            policy_id,
            scope_type,
            scope_id,
            version,
            policy_json,
            created_at,
            created_by,
            activated_at,
            activated_by
        FROM policy_registry_entries
        WHERE tenant_id = ? AND status = 'ACTIVE'
        ORDER BY activated_at DESC, created_at DESC
        LIMIT 500
        """,
        (effective_tenant,),
    )
    for row in policy_rows:
        policy_json = _parse_json(row.get("policy_json"))
        if bool(policy_json.get("strict_fail_closed")):
            active.append(
                {
                    "mode": "policy_strict_fail_closed",
                    "scope_type": str(row.get("scope_type") or ""),
                    "scope_id": str(row.get("scope_id") or ""),
                    "policy_id": str(row.get("policy_id") or ""),
                    "policy_version": int(row.get("version") or 0),
                    "enabled": True,
                    "reason": str(policy_json.get("strict_fail_closed_reason") or "").strip() or None,
                    "last_changed_by": str(row.get("activated_by") or row.get("created_by") or "").strip() or None,
                    "last_changed_at": _iso_datetime_or_none(row.get("activated_at") or row.get("created_at")),
                    "source": "policy_registry_entries",
                }
            )

    settings = storage.fetchone(
        """
        SELECT quota_enforcement_mode, security_state, security_reason, updated_at, updated_by
        FROM tenant_governance_settings
        WHERE tenant_id = ?
        LIMIT 1
        """,
        (effective_tenant,),
    ) or {}
    if str(settings.get("quota_enforcement_mode") or "").upper() == "HARD":
        active.append(
            {
                "mode": "quota_hard_enforcement",
                "scope_type": "tenant",
                "scope_id": effective_tenant,
                "enabled": True,
                "reason": "tenant quota enforcement mode is HARD",
                "last_changed_by": str(settings.get("updated_by") or "").strip() or None,
                "last_changed_at": _iso_datetime_or_none(settings.get("updated_at")),
                "source": "tenant_governance_settings",
                "updated_at": settings.get("updated_at"),
            }
        )
    if str(settings.get("security_state") or "").strip().lower() == "locked":
        active.append(
            {
                "mode": "tenant_locked",
                "scope_type": "tenant",
                "scope_id": effective_tenant,
                "enabled": True,
                "reason": str(settings.get("security_reason") or "").strip() or "tenant security state is locked",
                "last_changed_by": str(settings.get("updated_by") or "").strip() or None,
                "last_changed_at": _iso_datetime_or_none(settings.get("updated_at")),
                "source": "tenant_governance_settings",
                "updated_at": settings.get("updated_at"),
            }
        )

    strict_env_flags = [
        ("workflow_gate_strict_mode", "RELEASEGATE_STRICT_MODE", os.getenv("RELEASEGATE_STRICT_MODE")),
        ("kms_strict_mode", "RELEASEGATE_STRICT_KMS", os.getenv("RELEASEGATE_STRICT_KMS")),
        (
            "correlation_strict_mode",
            "RELEASEGATE_CORRELATION_STRICT",
            os.getenv("RELEASEGATE_CORRELATION_STRICT") or os.getenv("CORRELATION_STRICT"),
        ),
        ("independent_anchor_strict_mode", "RELEASEGATE_ANCHOR_STRICT", os.getenv("RELEASEGATE_ANCHOR_STRICT")),
        ("strict_fail_closed", "RELEASEGATE_STRICT_FAIL_CLOSED", os.getenv("RELEASEGATE_STRICT_FAIL_CLOSED")),
    ]
    for mode, env_var, raw in strict_env_flags:
        if str(raw or "").strip().lower() in {"1", "true", "yes", "on"}:
            active.append(
                {
                    "mode": mode,
                    "scope_type": "system",
                    "scope_id": "global",
                    "enabled": True,
                    "reason": f"enabled via environment variable {env_var}",
                    "last_changed_by": None,
                    "last_changed_at": None,
                    "source": "env",
                }
            )

    return active


def get_dashboard_overview(
    *,
    tenant_id: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
    blocked_limit: int = DEFAULT_BLOCKED_LIMIT,
    include_debug_timing: bool = False,
) -> Dict[str, Any]:
    total_started = perf_counter()
    timings: Dict[str, float] = {}

    started = perf_counter()
    effective_tenant = resolve_tenant_id(tenant_id)
    timings["resolve_tenant"] = round((perf_counter() - started) * 1000.0, 3)

    started = perf_counter()
    trend = list_integrity_trend(tenant_id=effective_tenant, window_days=window_days)
    timings["integrity_trend_load"] = round((perf_counter() - started) * 1000.0, 3)

    if not trend:
        started = perf_counter()
        compute_and_upsert_daily_rollup(
            tenant_id=effective_tenant,
            date_utc=_utc_now().date(),
        )
        timings["current_day_rollup_seed"] = round((perf_counter() - started) * 1000.0, 3)

        started = perf_counter()
        trend = list_integrity_trend(tenant_id=effective_tenant, window_days=window_days)
        timings["integrity_trend_reload"] = round((perf_counter() - started) * 1000.0, 3)

    started = perf_counter()
    blocked = list_recent_blocked_decisions(tenant_id=effective_tenant, limit=blocked_limit)
    timings["recent_blocked_load"] = round((perf_counter() - started) * 1000.0, 3)

    started = perf_counter()
    strict_modes = list_active_strict_modes(tenant_id=effective_tenant)
    timings["strict_modes_load"] = round((perf_counter() - started) * 1000.0, 3)

    if trend:
        started = perf_counter()
        latest = trend[-1]
        integrity_score = float(latest.get("integrity_score") or 0.0)
        drift_index = float(latest.get("drift_index") or 0.0)
        override_rate = float(latest.get("override_rate") or 0.0)
        drift_breakdown = latest.get("drift_breakdown") if isinstance(latest.get("drift_breakdown"), dict) else None
        timings["trend_extract"] = round((perf_counter() - started) * 1000.0, 3)
    else:
        integrity_score = 0.0
        drift_index = 0.0
        override_rate = 0.0
        drift_breakdown = None

    started = perf_counter()
    payload = {
        "tenant_id": effective_tenant,
        "window_days": _normalize_window_days(window_days),
        "integrity_score": round(integrity_score, 6),
        "integrity_trend": [
            {"date_utc": row["date_utc"], "value": row["integrity_score"]}
            for row in trend
        ],
        "drift_index": round(drift_index, 6),
        "drift_trend": [
            {"date_utc": row["date_utc"], "value": row["drift_index"]}
            for row in trend
        ],
        "override_rate": round(override_rate, 6),
        "override_rate_trend": [
            {
                "date_utc": row["date_utc"],
                "value": row["override_rate"],
                "override_count": int(row.get("override_count") or 0),
                "decision_count": int(row.get("decision_count") or 0),
            }
            for row in trend
        ],
        "drift": {
            "current": round(drift_index, 6),
            "breakdown": drift_breakdown if isinstance(drift_breakdown, dict) else None,
        },
        "active_strict_modes": strict_modes,
        "recent_blocked": blocked,
    }
    timings["payload_assembly"] = round((perf_counter() - started) * 1000.0, 3)
    timings["total_service"] = round((perf_counter() - total_started) * 1000.0, 3)
    if include_debug_timing:
        payload["debug_timing_ms"] = timings
    return payload


def list_dashboard_alerts(
    *,
    tenant_id: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_window = _normalize_window_days(window_days)
    start_date = (_utc_now().date() - timedelta(days=bounded_window - 1)).isoformat()
    rows = storage.fetchall(
        """
        SELECT
            date_utc,
            override_rate,
            drift_index,
            strict_mode_count,
            override_count,
            decision_count,
            details_json
        FROM governance_daily_metrics
        WHERE tenant_id = ? AND date_utc >= ?
        ORDER BY date_utc ASC
        """,
        (effective_tenant, start_date),
    )

    alerts: List[Dict[str, Any]] = []
    rolling_previous: List[Dict[str, Any]] = []
    current_override_abuse_index = 0.0
    for row in rows:
        day = _coerce_date_utc(row.get("date_utc") or _utc_now().date().isoformat())
        override_rate = _safe_float(row.get("override_rate"))
        drift_index = _safe_float(row.get("drift_index"))
        strict_mode_count = int(row.get("strict_mode_count") or 0)
        override_count = int(row.get("override_count") or 0)
        decision_count = int(row.get("decision_count") or 0)
        details = _parse_json(row.get("details_json"))

        stored_alerts = details.get("alerts") if isinstance(details.get("alerts"), list) else []
        for alert in stored_alerts:
            if not isinstance(alert, dict):
                continue
            alerts.append(
                {
                    "date_utc": _iso_date(alert.get("date_utc") or day.isoformat()),
                    "severity": str(alert.get("severity") or "medium").lower(),
                    "code": str(alert.get("code") or "UNKNOWN"),
                    "title": str(alert.get("title") or "Governance alert"),
                    "details": alert.get("details") if isinstance(alert.get("details"), dict) else {},
                }
            )

        computed_alerts = _build_daily_alerts(
            tenant_id=effective_tenant,
            day=day,
            override_rate=override_rate,
            drift_index=drift_index,
            strict_mode_count=strict_mode_count,
            decision_count=decision_count,
            override_count=override_count,
            prior_rows=rolling_previous,
        )
        existing_keys = {(str(item.get("date_utc")), str(item.get("code"))) for item in alerts}
        for alert in computed_alerts:
            key = (str(alert.get("date_utc")), str(alert.get("code")))
            if key not in existing_keys:
                alerts.append(alert)
                existing_keys.add(key)

        current_override_abuse_index = _safe_float(
            details.get("override_abuse_index"),
            default=override_rate,
        )
        rolling_previous.insert(0, row)
        if len(rolling_previous) > ALERT_BASELINE_DAYS:
            rolling_previous = rolling_previous[:ALERT_BASELINE_DAYS]

    sorted_alerts = sorted(
        alerts,
        key=lambda alert: (
            -int(_iso_date(alert.get("date_utc")).replace("-", "")),
            _severity_rank(str(alert.get("severity") or "medium")),
            str(alert.get("code") or ""),
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "window_days": bounded_window,
        "alerts": sorted_alerts,
        "current_override_abuse_index": round(current_override_abuse_index, 6),
    }


def compute_and_upsert_governance_daily_metrics(
    *,
    tenant_id: str,
    days: int = 30,
) -> Dict[str, Any]:
    return backfill_rollups(tenant_id=tenant_id, days=days)


def compute_and_upsert_daily_rollup(
    *,
    tenant_id: str,
    date_utc: date | datetime | str,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    day = _coerce_date_utc(date_utc)
    day_start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    day_cutoff = day_start + timedelta(days=1)
    metrics = get_tenant_governance_integrity(
        tenant_id=effective_tenant,
        window_days=30,
        now=day_cutoff,
    )
    strict_mode_count = len(list_active_strict_modes(tenant_id=effective_tenant))
    override_count = int((metrics.get("override_abuse") or {}).get("override_count") or 0)
    decision_count = int(metrics.get("decision_count") or 0)
    override_rate = _override_rate_from_counts(
        override_count=override_count,
        decision_count=decision_count,
    )
    abuse_payload = _rollup_override_abuse(
        override_count=override_count,
        decision_count=decision_count,
        metrics=metrics,
    )
    prior_rows = _fetch_prior_rollup_rows(
        tenant_id=effective_tenant,
        day=day,
        limit=ALERT_BASELINE_DAYS,
    )
    alerts = _build_daily_alerts(
        tenant_id=effective_tenant,
        day=day,
        override_rate=override_rate,
        drift_index=float(metrics.get("drift_index") or 0.0),
        strict_mode_count=strict_mode_count,
        decision_count=decision_count,
        override_count=override_count,
        prior_rows=prior_rows,
    )
    details_payload = dict(metrics)
    details_payload.update(abuse_payload)
    details_payload["alerts"] = alerts
    details_payload["alert_counts"] = _collect_alert_counts(alerts)
    computed_at = _utc_now().isoformat()
    storage.execute(
        """
        INSERT INTO governance_daily_metrics (
            tenant_id, date_utc, integrity_score, drift_index, override_rate, blocked_count,
            strict_mode_count, override_count, decision_count, computed_at, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, date_utc) DO UPDATE SET
            integrity_score = EXCLUDED.integrity_score,
            drift_index = EXCLUDED.drift_index,
            override_rate = EXCLUDED.override_rate,
            blocked_count = EXCLUDED.blocked_count,
            strict_mode_count = EXCLUDED.strict_mode_count,
            override_count = EXCLUDED.override_count,
            decision_count = EXCLUDED.decision_count,
            computed_at = EXCLUDED.computed_at,
            details_json = EXCLUDED.details_json
        """,
        (
            effective_tenant,
            day.isoformat(),
            float(metrics.get("governance_integrity_score") or 0.0),
            float(metrics.get("drift_index") or 0.0),
            float(override_rate),
            int(metrics.get("deny_count") or 0),
            int(strict_mode_count),
            override_count,
            decision_count,
            computed_at,
            json.dumps(details_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "date_utc": day.isoformat(),
        "computed_at": computed_at,
        "integrity_score": float(metrics.get("governance_integrity_score") or 0.0),
        "drift_index": float(metrics.get("drift_index") or 0.0),
        "override_rate": float(override_rate),
        "override_abuse_index": float(abuse_payload.get("override_abuse_index") or 0.0),
        "alerts": alerts,
        "blocked_count": int(metrics.get("deny_count") or 0),
    }


def backfill_rollups(
    *,
    tenant_id: str,
    days: int = 30,
    anchor_date_utc: Optional[date | datetime | str] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_days = max(1, min(int(days or DEFAULT_WINDOW_DAYS), MAX_WINDOW_DAYS))
    anchor_date = _coerce_date_utc(anchor_date_utc) if anchor_date_utc is not None else _utc_now().date()
    start_date = anchor_date - timedelta(days=bounded_days - 1)
    current = start_date
    written = 0
    while current <= anchor_date:
        compute_and_upsert_daily_rollup(
            tenant_id=effective_tenant,
            date_utc=current,
        )
        written += 1
        current += timedelta(days=1)
    return {
        "tenant_id": effective_tenant,
        "days_requested": bounded_days,
        "days_written": written,
        "start_date_utc": start_date.isoformat(),
        "end_date_utc": anchor_date.isoformat(),
    }
