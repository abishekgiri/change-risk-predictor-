from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _parse_day(value: Optional[str]) -> date:
    if not value:
        return datetime.now(timezone.utc).date()
    return date.fromisoformat(str(value))


def _day_window(day: date) -> Tuple[str, str]:
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    return start.isoformat(), end.isoformat()


def _load_decision_risk_map(*, tenant_id: str, decision_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    ids = [str(item) for item in decision_ids if str(item).strip()]
    if not ids:
        return {}
    storage = get_storage_backend()
    placeholders = ",".join(["?"] * len(ids))
    rows = storage.fetchall(
        f"""
        SELECT decision_id, full_decision_json
        FROM audit_decisions
        WHERE tenant_id = ? AND decision_id IN ({placeholders})
        """,
        [tenant_id, *ids],
    )
    result: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        raw = row.get("full_decision_json")
        payload: Dict[str, Any] = {}
        if isinstance(raw, str) and raw.strip():
            try:
                loaded = json.loads(raw)
                if isinstance(loaded, dict):
                    payload = loaded
            except Exception:
                payload = {}
        result[str(row.get("decision_id") or "")] = payload
    return result


def _is_high_risk(decision_payload: Dict[str, Any]) -> bool:
    risk_level = str(decision_payload.get("risk_level") or "").upper()
    if risk_level in {"HIGH", "CRITICAL"}:
        return True
    score = decision_payload.get("risk_score")
    try:
        if score is not None and float(score) >= 0.7:
            return True
    except Exception:
        pass
    return False


def rollup_override_metrics_day(*, tenant_id: str, date_utc: Optional[str] = None) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    day = _parse_day(date_utc)
    day_key = day.isoformat()
    start_iso, end_iso = _day_window(day)

    rows = storage.fetchall(
        """
        SELECT chain_id, actor, issue_key, event_type, decision_id
        FROM jira_lock_events
        WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
        """,
        (effective_tenant, start_iso, end_iso),
    )
    decision_ids = {str(row.get("decision_id") or "") for row in rows if row.get("decision_id")}
    risk_map = _load_decision_risk_map(tenant_id=effective_tenant, decision_ids=decision_ids)

    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    distinct_issues: Dict[Tuple[str, str], set[str]] = defaultdict(set)
    for row in rows:
        chain_id = str(row.get("chain_id") or "unscoped")
        actor = str(row.get("actor") or "unknown")
        key = (chain_id, actor)
        bucket = groups.setdefault(
            key,
            {
                "overrides_total": 0,
                "locks_total": 0,
                "unlocks_total": 0,
                "override_expires_total": 0,
                "high_risk_overrides_total": 0,
            },
        )
        event_type = str(row.get("event_type") or "").upper()
        if event_type == "OVERRIDE":
            bucket["overrides_total"] += 1
            decision_payload = risk_map.get(str(row.get("decision_id") or ""), {})
            if _is_high_risk(decision_payload):
                bucket["high_risk_overrides_total"] += 1
        elif event_type == "LOCK":
            bucket["locks_total"] += 1
        elif event_type == "UNLOCK":
            bucket["unlocks_total"] += 1
        elif event_type == "OVERRIDE_EXPIRE":
            bucket["override_expires_total"] += 1
        issue_key = str(row.get("issue_key") or "").strip()
        if issue_key:
            distinct_issues[key].add(issue_key)

    storage.execute(
        """
        DELETE FROM governance_override_metrics_daily
        WHERE tenant_id = ? AND date_utc = ?
        """,
        (effective_tenant, day_key),
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    for (chain_id, actor), bucket in groups.items():
        storage.execute(
            """
            INSERT INTO governance_override_metrics_daily (
                tenant_id, date_utc, chain_id, actor,
                overrides_total, locks_total, unlocks_total, override_expires_total,
                high_risk_overrides_total, distinct_issues_total, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                day_key,
                chain_id,
                actor,
                int(bucket["overrides_total"]),
                int(bucket["locks_total"]),
                int(bucket["unlocks_total"]),
                int(bucket["override_expires_total"]),
                int(bucket["high_risk_overrides_total"]),
                int(len(distinct_issues.get((chain_id, actor), set()))),
                now_iso,
            ),
        )

    return {
        "tenant_id": effective_tenant,
        "date_utc": day_key,
        "groups": len(groups),
        "events_scanned": len(rows),
    }


def _dates_between(start: date, end: date) -> List[date]:
    current = start
    result: List[date] = []
    while current <= end:
        result.append(current)
        current += timedelta(days=1)
    return result


def get_override_metrics_summary(
    *,
    tenant_id: str,
    days: int = 30,
    top_n: int = 10,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    window_days = max(1, min(int(days), 90))

    end_day = datetime.now(timezone.utc).date()
    start_day = end_day - timedelta(days=window_days - 1)
    for day in _dates_between(start_day, end_day):
        rollup_override_metrics_day(tenant_id=effective_tenant, date_utc=day.isoformat())

    rows = storage.fetchall(
        """
        SELECT *
        FROM governance_override_metrics_daily
        WHERE tenant_id = ? AND date_utc >= ? AND date_utc <= ?
        """,
        (effective_tenant, start_day.isoformat(), end_day.isoformat()),
    )

    seven_day_cutoff = end_day - timedelta(days=6)
    totals_7d = {"overrides": 0, "locks": 0, "unlocks": 0}
    totals_30d = {"overrides": 0, "locks": 0, "unlocks": 0, "high_risk_overrides": 0}
    actor_overrides_30d: Dict[str, int] = defaultdict(int)
    actor_high_risk_30d: Dict[str, int] = defaultdict(int)
    actor_distinct_scope_30d: Dict[str, set[str]] = defaultdict(set)
    actor_repeat_scope_30d: Dict[str, int] = defaultdict(int)
    actor_scope_counts: Dict[Tuple[str, str], int] = defaultdict(int)

    for row in rows:
        row_day = date.fromisoformat(str(row.get("date_utc")))
        overrides = int(row.get("overrides_total") or 0)
        locks = int(row.get("locks_total") or 0)
        unlocks = int(row.get("unlocks_total") or 0)
        high_risk = int(row.get("high_risk_overrides_total") or 0)
        actor = str(row.get("actor") or "unknown")
        chain_id = str(row.get("chain_id") or "unscoped")

        totals_30d["overrides"] += overrides
        totals_30d["locks"] += locks
        totals_30d["unlocks"] += unlocks
        totals_30d["high_risk_overrides"] += high_risk

        if row_day >= seven_day_cutoff:
            totals_7d["overrides"] += overrides
            totals_7d["locks"] += locks
            totals_7d["unlocks"] += unlocks

        actor_overrides_30d[actor] += overrides
        actor_high_risk_30d[actor] += high_risk
        if overrides > 0:
            actor_distinct_scope_30d[actor].add(chain_id)
            actor_scope_counts[(actor, chain_id)] += overrides

    for (actor, _chain_id), count in actor_scope_counts.items():
        if count > 1:
            actor_repeat_scope_30d[actor] += count

    top_overrides = sorted(actor_overrides_30d.items(), key=lambda item: (-item[1], item[0]))[: max(1, top_n)]
    top_high_risk = sorted(actor_high_risk_30d.items(), key=lambda item: (-item[1], item[0]))[: max(1, top_n)]

    high_risk_rate = 0.0
    if totals_30d["overrides"] > 0:
        high_risk_rate = totals_30d["high_risk_overrides"] / totals_30d["overrides"]

    return {
        "tenant_id": effective_tenant,
        "window_days": window_days,
        "from_date_utc": start_day.isoformat(),
        "to_date_utc": end_day.isoformat(),
        "metrics": {
            "overrides_total_7d": totals_7d["overrides"],
            "overrides_total_30d": totals_30d["overrides"],
            "locks_total_7d": totals_7d["locks"],
            "unlocks_total_7d": totals_7d["unlocks"],
            "high_risk_overrides_total_30d": totals_30d["high_risk_overrides"],
            "high_risk_override_rate_30d": round(high_risk_rate, 6),
        },
        "overrides_by_actor_30d": [
            {"actor": actor, "count": count, "distinct_scopes": len(actor_distinct_scope_30d.get(actor, set()))}
            for actor, count in top_overrides
        ],
        "high_risk_overrides_by_actor_30d": [
            {"actor": actor, "count": count}
            for actor, count in top_high_risk
        ],
        "repeat_override_same_scope_30d": [
            {"actor": actor, "count": count}
            for actor, count in sorted(actor_repeat_scope_30d.items(), key=lambda item: (-item[1], item[0]))
            if count > 0
        ],
    }
