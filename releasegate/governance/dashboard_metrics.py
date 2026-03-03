from __future__ import annotations

import json
import os
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from releasegate.governance.integrity import get_tenant_governance_integrity
from releasegate.quota.quota_service import get_tenant_governance_metrics
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


DEFAULT_WINDOW_DAYS = 30
MAX_WINDOW_DAYS = 90
DEFAULT_BLOCKED_LIMIT = 25
MAX_BLOCKED_LIMIT = 100


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


def list_integrity_trend(
    *,
    tenant_id: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_window = _normalize_window_days(window_days)
    start_date = (_utc_now().date() - timedelta(days=bounded_window - 1)).isoformat()
    rows = storage.fetchall(
        """
        SELECT date_utc, integrity_score, drift_index, override_rate, blocked_count
        FROM governance_daily_metrics
        WHERE tenant_id = ? AND date_utc >= ?
        ORDER BY date_utc ASC
        """,
        (effective_tenant, start_date),
    )
    return [
        {
            "date_utc": _iso_date(row.get("date_utc")),
            "integrity_score": float(row.get("integrity_score") or 0.0),
            "drift_index": float(row.get("drift_index") or 0.0),
            "override_rate": float(row.get("override_rate") or 0.0),
            "blocked_count": int(row.get("blocked_count") or 0),
        }
        for row in rows
    ]


def list_recent_blocked_decisions(
    *,
    tenant_id: str,
    limit: int = DEFAULT_BLOCKED_LIMIT,
) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_limit = _normalize_limit(limit)
    rows = storage.fetchall(
        """
        SELECT decision_id, created_at, release_status, full_decision_json, policy_hash
        FROM audit_decisions
        WHERE tenant_id = ?
          AND release_status IN ('BLOCKED', 'ERROR', 'DENIED')
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (effective_tenant, bounded_limit),
    )

    items: List[Dict[str, Any]] = []
    for row in rows:
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
                "actor": str(request.get("actor_account_id") or request.get("actor_id") or ""),
                "environment": str(request.get("environment") or ""),
                "project_key": str(request.get("project_key") or ""),
                "policy_hash": str(row.get("policy_hash") or ""),
            }
        )
    return items


def list_active_strict_modes(*, tenant_id: str) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    active: List[Dict[str, Any]] = []

    policy_rows = storage.fetchall(
        """
        SELECT policy_id, scope_type, scope_id, version, policy_json
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
                    "source": "policy_registry_entries",
                }
            )

    settings = storage.fetchone(
        """
        SELECT quota_enforcement_mode, security_state, updated_at
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
                "source": "tenant_governance_settings",
                "updated_at": settings.get("updated_at"),
            }
        )

    strict_env_flags = {
        "workflow_gate_strict_mode": os.getenv("RELEASEGATE_STRICT_MODE"),
        "kms_strict_mode": os.getenv("RELEASEGATE_STRICT_KMS"),
        "correlation_strict_mode": os.getenv("RELEASEGATE_CORRELATION_STRICT") or os.getenv("CORRELATION_STRICT"),
        "independent_anchor_strict_mode": os.getenv("RELEASEGATE_ANCHOR_STRICT"),
        "strict_fail_closed": os.getenv("RELEASEGATE_STRICT_FAIL_CLOSED"),
    }
    for mode, raw in strict_env_flags.items():
        if str(raw or "").strip().lower() in {"1", "true", "yes", "on"}:
            active.append(
                {
                    "mode": mode,
                    "scope_type": "system",
                    "scope_id": "global",
                    "enabled": True,
                    "source": "env",
                }
            )

    return active


def get_dashboard_overview(
    *,
    tenant_id: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
    blocked_limit: int = DEFAULT_BLOCKED_LIMIT,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    trend = list_integrity_trend(tenant_id=effective_tenant, window_days=window_days)
    blocked = list_recent_blocked_decisions(tenant_id=effective_tenant, limit=blocked_limit)
    strict_modes = list_active_strict_modes(tenant_id=effective_tenant)

    if trend:
        latest = trend[-1]
        integrity_score = float(latest.get("integrity_score") or 0.0)
        drift_index = float(latest.get("drift_index") or 0.0)
        override_rate = float(latest.get("override_rate") or 0.0)
    else:
        integrity_payload = get_tenant_governance_integrity(
            tenant_id=effective_tenant,
            window_days=min(_normalize_window_days(window_days), 90),
        )
        governance_metrics = get_tenant_governance_metrics(tenant_id=effective_tenant)
        integrity_score = float(integrity_payload.get("governance_integrity_score") or 0.0)
        drift_index = float(integrity_payload.get("drift_index") or 0.0)
        override_rate = float((integrity_payload.get("override_abuse") or {}).get("override_rate") or 0.0)
        trend = [
            {
                "date_utc": _utc_now().date().isoformat(),
                "integrity_score": integrity_score,
                "drift_index": drift_index,
                "override_rate": override_rate,
                "blocked_count": int(governance_metrics.get("denies_month") or 0),
            }
        ]

    return {
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
            {"date_utc": row["date_utc"], "value": row["override_rate"]}
            for row in trend
        ],
        "active_strict_modes": strict_modes,
        "recent_blocked": blocked,
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
    init_db()
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
            float((metrics.get("override_abuse") or {}).get("override_rate") or 0.0),
            int(metrics.get("deny_count") or 0),
            int(strict_mode_count),
            int((metrics.get("override_abuse") or {}).get("override_count") or 0),
            int(metrics.get("decision_count") or 0),
            computed_at,
            json.dumps(metrics, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "date_utc": day.isoformat(),
        "computed_at": computed_at,
        "integrity_score": float(metrics.get("governance_integrity_score") or 0.0),
        "drift_index": float(metrics.get("drift_index") or 0.0),
        "override_rate": float((metrics.get("override_abuse") or {}).get("override_rate") or 0.0),
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
