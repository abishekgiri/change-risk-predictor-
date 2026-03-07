from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from releasegate.policy.diff_impact import build_policy_impact_diff
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id


_ALLOWED_WINDOWS = {30, 60, 90}
_DRIFT_DECAY_DAYS = 90.0
_OVERRIDE_RATE_THRESHOLD = 0.20
_REPEAT_ACTOR_THRESHOLD = 0.40
_EXPIRED_OVERRIDE_THRESHOLD = 0.05
_PROD_CLUSTER_THRESHOLD = 0.60
_DENY_RATE_IDEAL_MIDPOINT = 0.125

_DRIFT_WEIGHTS: Dict[str, int] = {
    "WEAKEN_RISK_THRESHOLD": 3,
    "WEAKEN_APPROVAL_REQUIREMENT": 4,
    "WEAKEN_REQUIRED_ROLES": 3,
    "WEAKEN_PROTECTED_STATUSES": 5,
    "WEAKEN_BLOCKING_RULE_REMOVED": 6,
    "WEAKEN_RULE_RESULT": 4,
    "WEAKEN_STRICT_FAIL_CLOSED": 4,
    "OVERRIDE_TTL_INCREASE": 2,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = _normalize_text(value)
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_json(value: Any, fallback: Any) -> Any:
    if isinstance(value, type(fallback)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return fallback
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return fallback
        if isinstance(parsed, type(fallback)):
            return parsed
    return fallback


def _extract_ttl_values(payload: Any, prefix: str = "") -> Dict[str, float]:
    values: Dict[str, float] = {}
    if isinstance(payload, dict):
        for raw_key, value in payload.items():
            key = _normalize_text(raw_key)
            if not key:
                continue
            path = f"{prefix}.{key}" if prefix else key
            key_lower = key.lower()
            path_lower = path.lower()
            if (
                isinstance(value, (int, float))
                and "ttl" in key_lower
                and ("override" in path_lower or "override" in key_lower)
            ):
                values[path] = float(value)
            values.update(_extract_ttl_values(value, prefix=path))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            values.update(_extract_ttl_values(item, prefix=f"{prefix}[{index}]"))
    return values


def _ttl_increase_events(previous_policy: Dict[str, Any], next_policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    previous = _extract_ttl_values(previous_policy)
    current = _extract_ttl_values(next_policy)
    events: List[Dict[str, Any]] = []
    for path in sorted(set(previous.keys()) | set(current.keys())):
        if path not in previous or path not in current:
            continue
        old_value = float(previous[path])
        new_value = float(current[path])
        if new_value <= old_value:
            continue
        events.append(
            {
                "code": "OVERRIDE_TTL_INCREASE",
                "path": path,
                "from": old_value,
                "to": new_value,
            }
        )
    return events


def _drift_weight(code: str) -> int:
    return int(_DRIFT_WEIGHTS.get(str(code), 1))


def _window_bounds(window_days: int, now: datetime) -> Tuple[datetime, datetime]:
    if int(window_days) not in _ALLOWED_WINDOWS:
        raise ValueError("window_days must be one of 30, 60, 90")
    return now - timedelta(days=int(window_days)), now


def _fetch_policy_history(*, tenant_id: str) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    return storage.fetchall(
        """
        SELECT
            policy_id,
            scope_type,
            scope_id,
            version,
            policy_json,
            created_at,
            status
        FROM policy_registry_entries
        WHERE tenant_id = ?
        ORDER BY scope_type ASC, scope_id ASC, version ASC
        """,
        (tenant_id,),
    )


def _compute_policy_drift(
    *,
    tenant_id: str,
    window_start: datetime,
    window_days: int,
    now: datetime,
) -> Dict[str, Any]:
    rows = _fetch_policy_history(tenant_id=tenant_id)
    by_scope: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        scope_type = _normalize_text(row.get("scope_type")) or "unknown"
        scope_id = _normalize_text(row.get("scope_id")) or "unknown"
        by_scope[(scope_type, scope_id)].append(row)

    scope_scores: List[Dict[str, Any]] = []
    total_score = 0.0
    total_recent_events = 0
    signal_totals: Counter[str] = Counter()

    for (scope_type, scope_id), versions in by_scope.items():
        if len(versions) < 2:
            continue
        versions_sorted = sorted(versions, key=lambda row: int(row.get("version") or 0))
        scope_score = 0.0
        recent_event_count = 0
        scope_signal_counts: Counter[str] = Counter()
        recent_points = 0.0
        older_points = 0.0
        last_change: Optional[datetime] = None
        latest_entry = versions_sorted[-1]

        for previous, current in zip(versions_sorted, versions_sorted[1:]):
            changed_at = _parse_datetime(current.get("created_at"))
            if changed_at is None or changed_at < window_start:
                continue
            previous_json = _parse_json(previous.get("policy_json"), {})
            current_json = _parse_json(current.get("policy_json"), {})
            if not isinstance(previous_json, dict) or not isinstance(current_json, dict):
                continue

            diff = build_policy_impact_diff(
                tenant_id=tenant_id,
                current_policy_id=None,
                current_policy_version=None,
                current_policy_json=previous_json,
                candidate_policy_id=None,
                candidate_policy_version=None,
                candidate_policy_json=current_json,
            )
            weakening_codes = [
                str(item.get("code") or "")
                for item in (diff.get("warnings") or [])
                if isinstance(item, dict) and str(item.get("code") or "").startswith("WEAKEN_")
            ]
            ttl_events = _ttl_increase_events(previous_json, current_json)
            ttl_codes = [str(item.get("code") or "") for item in ttl_events]
            all_codes = [code for code in (weakening_codes + ttl_codes) if code]
            if not all_codes:
                continue

            points = float(sum(_drift_weight(code) for code in all_codes))
            days_since = max(0.0, (now - changed_at).total_seconds() / 86400.0)
            decay = math.exp(-(days_since / _DRIFT_DECAY_DAYS))
            weighted_points = points * decay
            scope_score += weighted_points
            scope_signal_counts.update(all_codes)

            if days_since <= min(30.0, float(window_days)):
                recent_event_count += 1
            if days_since <= float(window_days) / 2.0:
                recent_points += weighted_points
            else:
                older_points += weighted_points

            if last_change is None or changed_at > last_change:
                last_change = changed_at

        if scope_score <= 0:
            continue

        trend = "STABLE"
        if recent_points > (older_points * 1.1):
            trend = "INCREASING"
        elif older_points > (recent_points * 1.1):
            trend = "DECREASING"

        payload = {
            "policy_id": _normalize_text(latest_entry.get("policy_id")) or None,
            "scope_type": scope_type,
            "scope_id": scope_id,
            "version": int(latest_entry.get("version") or 0),
            "drift_score": round(scope_score, 3),
            "recent_weakening_events": recent_event_count,
            "last_change": last_change.isoformat() if last_change is not None else None,
            "drift_trend": trend,
            "weakening_signal_counts": dict(scope_signal_counts),
        }
        scope_scores.append(payload)
        total_score += scope_score
        total_recent_events += recent_event_count
        signal_totals.update(scope_signal_counts)

    scope_scores.sort(key=lambda item: float(item.get("drift_score") or 0.0), reverse=True)
    policy_count = len(scope_scores)
    drift_index = (total_score / float(policy_count)) if policy_count > 0 else 0.0

    return {
        "drift_index": round(drift_index, 3),
        "drift_score_total": round(total_score, 3),
        "policy_count": policy_count,
        "recent_weakening_events": total_recent_events,
        "signal_totals": dict(signal_totals),
        "policies": scope_scores,
    }


def _extract_decision_request(full_decision_json: Any) -> Dict[str, Any]:
    payload = _parse_json(full_decision_json, {})
    if not isinstance(payload, dict):
        return {}
    input_snapshot = payload.get("input_snapshot")
    if not isinstance(input_snapshot, dict):
        return {}
    request = input_snapshot.get("request")
    if not isinstance(request, dict):
        return {}
    return request


def _count_expired_override_attempts(*, tenant_id: str, window_start: datetime, window_end: datetime) -> int:
    storage = get_storage_backend()
    rows = storage.fetchall(
        """
        SELECT full_decision_json
        FROM audit_decisions
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
          AND full_decision_json LIKE ?
        """,
        (tenant_id, window_start.isoformat(), window_end.isoformat(), "%OVERRIDE_EXPIRED%"),
    )
    count = 0
    for row in rows:
        payload = _parse_json(row.get("full_decision_json"), {})
        reason_code = _normalize_text((payload or {}).get("reason_code"))
        if reason_code == "OVERRIDE_EXPIRED":
            count += 1
    return count


def _count_sod_violations(*, tenant_id: str, window_start: datetime, window_end: datetime) -> int:
    storage = get_storage_backend()
    decision_rows = storage.fetchall(
        """
        SELECT full_decision_json
        FROM audit_decisions
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
          AND full_decision_json LIKE ?
        """,
        (tenant_id, window_start.isoformat(), window_end.isoformat(), "%SOD_%"),
    )
    decision_count = 0
    for row in decision_rows:
        payload = _parse_json(row.get("full_decision_json"), {})
        reason_code = _normalize_text((payload or {}).get("reason_code"))
        if reason_code.startswith("SOD_"):
            decision_count += 1

    anomaly_rows = storage.fetchall(
        """
        SELECT details_json
        FROM tenant_security_anomaly_events
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
          AND signal_type = 'failed_override_attempt'
        """,
        (tenant_id, window_start.isoformat(), window_end.isoformat()),
    )
    anomaly_count = 0
    for row in anomaly_rows:
        details = _parse_json(row.get("details_json"), {})
        if not isinstance(details, dict):
            continue
        reason_code = _normalize_text(details.get("reason_code"))
        if reason_code.startswith("SOD_") or details.get("sod_rule"):
            anomaly_count += 1

    return decision_count + anomaly_count


def _compute_override_abuse(
    *,
    tenant_id: str,
    window_start: datetime,
    window_end: datetime,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    override_rows = storage.fetchall(
        """
        SELECT
            o.override_id,
            o.actor,
            o.decision_id,
            o.created_at,
            d.full_decision_json
        FROM audit_overrides o
        LEFT JOIN audit_decisions d
          ON o.tenant_id = d.tenant_id
         AND o.decision_id = d.decision_id
        WHERE o.tenant_id = ?
          AND o.created_at >= ?
          AND o.created_at <= ?
        """,
        (tenant_id, window_start.isoformat(), window_end.isoformat()),
    )

    transition_count_row = storage.fetchone(
        """
        SELECT COUNT(1) AS transition_count
        FROM decision_transition_links
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
        """,
        (tenant_id, window_start.isoformat(), window_end.isoformat()),
    ) or {}

    protected_transitions = int(transition_count_row.get("transition_count") or 0)
    override_count = len(override_rows)
    override_rate = (float(override_count) / float(protected_transitions)) if protected_transitions > 0 else 0.0

    actor_counts: Counter[str] = Counter()
    cluster_counts: Counter[str] = Counter()
    prod_cluster_count = 0

    for row in override_rows:
        actor = _normalize_text(row.get("actor")) or "unknown"
        actor_counts.update([actor])
        request = _extract_decision_request(row.get("full_decision_json"))
        environment = _normalize_lower(request.get("environment")) or "unknown"
        project_key = _normalize_lower(request.get("project_key")) or "unknown"
        context_overrides = request.get("context_overrides") if isinstance(request.get("context_overrides"), dict) else {}
        workflow_id = _normalize_lower(context_overrides.get("workflow_id") or request.get("workflow_id") or request.get("transition_name")) or "unknown"
        cluster_key = f"{environment}|{workflow_id}|{project_key}"
        cluster_counts.update([cluster_key])
        if environment == "prod":
            prod_cluster_count += 1

    top_actor = None
    top_actor_share = 0.0
    if override_count > 0 and actor_counts:
        top_actor, top_actor_count = actor_counts.most_common(1)[0]
        top_actor_share = float(top_actor_count) / float(override_count)

    hotspot_cluster = None
    hotspot_cluster_share = 0.0
    if override_count > 0 and cluster_counts:
        hotspot_cluster, hotspot_count = cluster_counts.most_common(1)[0]
        hotspot_cluster_share = float(hotspot_count) / float(override_count)

    prod_cluster_ratio = (float(prod_cluster_count) / float(override_count)) if override_count > 0 else 0.0
    expired_override_attempts = _count_expired_override_attempts(
        tenant_id=tenant_id,
        window_start=window_start,
        window_end=window_end,
    )
    attempted_override_actions = override_count + expired_override_attempts
    expired_override_rate = (
        float(expired_override_attempts) / float(attempted_override_actions)
        if attempted_override_actions > 0
        else 0.0
    )

    abuse_score = 0
    if override_rate > _OVERRIDE_RATE_THRESHOLD:
        abuse_score += 5
    if top_actor_share > _REPEAT_ACTOR_THRESHOLD:
        abuse_score += 6
    if expired_override_rate > _EXPIRED_OVERRIDE_THRESHOLD:
        abuse_score += 4
    if prod_cluster_ratio > _PROD_CLUSTER_THRESHOLD:
        abuse_score += 5

    return {
        "override_rate": round(override_rate, 6),
        "override_count": override_count,
        "protected_transition_count": protected_transitions,
        "top_actor": top_actor,
        "top_actor_share": round(top_actor_share, 6),
        "repeat_actor_flag": bool(top_actor_share > _REPEAT_ACTOR_THRESHOLD),
        "expired_override_attempts": expired_override_attempts,
        "expired_override_rate": round(expired_override_rate, 6),
        "override_cluster_hotspot": hotspot_cluster,
        "override_cluster_hotspot_share": round(hotspot_cluster_share, 6),
        "prod_cluster_ratio": round(prod_cluster_ratio, 6),
        "override_abuse_score": int(abuse_score),
    }


def _compute_decision_stats(
    *,
    tenant_id: str,
    window_start: datetime,
    window_end: datetime,
) -> Dict[str, Any]:
    storage = get_storage_backend()
    totals = storage.fetchone(
        """
        SELECT COUNT(1) AS decision_count
        FROM audit_decisions
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
        """,
        (tenant_id, window_start.isoformat(), window_end.isoformat()),
    ) or {}
    denies = storage.fetchone(
        """
        SELECT COUNT(1) AS deny_count
        FROM audit_decisions
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at <= ?
          AND release_status IN ('BLOCKED', 'ERROR')
        """,
        (tenant_id, window_start.isoformat(), window_end.isoformat()),
    ) or {}
    decision_count = int(totals.get("decision_count") or 0)
    deny_count = int(denies.get("deny_count") or 0)
    deny_rate = (float(deny_count) / float(decision_count)) if decision_count > 0 else 0.0
    return {
        "decision_count": decision_count,
        "deny_count": deny_count,
        "deny_rate": round(deny_rate, 6),
    }


def _integrity_risk_level(score: float) -> str:
    if score >= 80.0:
        return "STABLE"
    if score >= 60.0:
        return "WATCH"
    return "CRITICAL"


def get_tenant_governance_integrity(
    *,
    tenant_id: str,
    window_days: int = 90,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    anchor = now.astimezone(timezone.utc) if isinstance(now, datetime) else _utc_now()
    window_start, window_end = _window_bounds(int(window_days), anchor)

    drift = _compute_policy_drift(
        tenant_id=effective_tenant,
        window_start=window_start,
        window_days=int(window_days),
        now=anchor,
    )
    abuse = _compute_override_abuse(
        tenant_id=effective_tenant,
        window_start=window_start,
        window_end=window_end,
    )
    decisions = _compute_decision_stats(
        tenant_id=effective_tenant,
        window_start=window_start,
        window_end=window_end,
    )
    sod_violation_count = _count_sod_violations(
        tenant_id=effective_tenant,
        window_start=window_start,
        window_end=window_end,
    )

    drift_index = float(drift.get("drift_index") or 0.0)
    override_abuse_score = float(abuse.get("override_abuse_score") or 0.0)
    deny_rate = float(decisions.get("deny_rate") or 0.0)

    governance_integrity_score = 100.0
    governance_integrity_score -= drift_index * 1.2
    governance_integrity_score -= override_abuse_score * 1.5
    governance_integrity_score -= float(sod_violation_count) * 3.0
    governance_integrity_score -= abs(deny_rate - _DENY_RATE_IDEAL_MIDPOINT) * 50.0
    governance_integrity_score = max(0.0, min(100.0, governance_integrity_score))

    return {
        "tenant_id": effective_tenant,
        "window_days": int(window_days),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "governance_integrity_score": round(governance_integrity_score, 3),
        "risk_level": _integrity_risk_level(governance_integrity_score),
        "drift_index": round(drift_index, 3),
        "override_abuse_score": int(override_abuse_score),
        "deny_rate": round(deny_rate, 6),
        "separation_of_duties_violations": int(sod_violation_count),
        "decision_count": int(decisions.get("decision_count") or 0),
        "deny_count": int(decisions.get("deny_count") or 0),
        "policy_drift": drift,
        "override_abuse": abuse,
        "score_components": {
            "drift_penalty": round(drift_index * 1.2, 3),
            "override_penalty": round(override_abuse_score * 1.5, 3),
            "sod_penalty": round(float(sod_violation_count) * 3.0, 3),
            "deny_rate_penalty": round(abs(deny_rate - _DENY_RATE_IDEAL_MIDPOINT) * 50.0, 3),
        },
    }
