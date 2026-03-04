from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from releasegate.quota.quota_models import (
    QUOTA_KIND_ANCHORS,
    QUOTA_KIND_DECISIONS,
    QUOTA_KIND_OVERRIDES,
    TenantQuotaExceededError,
    TenantQuotaLimits,
)
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _month_start_iso(now: datetime) -> str:
    return datetime(now.year, now.month, 1, tzinfo=timezone.utc).isoformat()


def _day_start_iso(now: datetime) -> str:
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc).isoformat()


def _next_month_start(now: datetime) -> datetime:
    if now.month == 12:
        return datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
    return datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)


def _normalize_mode(value: Optional[str]) -> str:
    mode = str(value or "HARD").strip().upper()
    if mode not in {"HARD", "SOFT"}:
        return "HARD"
    return mode


def _normalize_limit(value: Any) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    parsed = int(text)
    if parsed < 0:
        raise ValueError("quota values must be >= 0")
    return parsed


def _period_type_for_quota(quota_kind: str) -> str:
    if quota_kind == QUOTA_KIND_ANCHORS:
        return "daily"
    return "monthly"


def _counter_column_for_quota(quota_kind: str) -> str:
    if quota_kind == QUOTA_KIND_DECISIONS:
        return "decisions_count"
    if quota_kind == QUOTA_KIND_ANCHORS:
        return "anchors_count"
    if quota_kind == QUOTA_KIND_OVERRIDES:
        return "overrides_count"
    raise ValueError(f"Unsupported quota kind: {quota_kind}")


def _limit_for_quota(limits: TenantQuotaLimits, quota_kind: str) -> Optional[int]:
    if quota_kind == QUOTA_KIND_DECISIONS:
        return limits.max_decisions_per_month
    if quota_kind == QUOTA_KIND_ANCHORS:
        return limits.max_anchors_per_day
    if quota_kind == QUOTA_KIND_OVERRIDES:
        return limits.max_overrides_per_month
    raise ValueError(f"Unsupported quota kind: {quota_kind}")


def _ensure_governance_tables() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_governance_settings (
            tenant_id TEXT PRIMARY KEY,
            max_decisions_per_month INTEGER,
            max_anchors_per_day INTEGER,
            max_overrides_per_month INTEGER,
            quota_enforcement_mode TEXT NOT NULL DEFAULT 'HARD',
            security_state TEXT NOT NULL DEFAULT 'normal',
            security_reason TEXT,
            security_since TEXT,
            updated_at TEXT NOT NULL,
            updated_by TEXT
        )
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_governance_settings_security_state
        ON tenant_governance_settings(security_state, updated_at)
        """
    )

    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_usage_counters (
            tenant_id TEXT NOT NULL,
            period_type TEXT NOT NULL,
            period_start TEXT NOT NULL,
            decisions_count INTEGER NOT NULL DEFAULT 0,
            anchors_count INTEGER NOT NULL DEFAULT 0,
            overrides_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, period_type, period_start)
        )
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_usage_counters_tenant_updated
        ON tenant_usage_counters(tenant_id, updated_at DESC)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_usage_counters_period
        ON tenant_usage_counters(period_type, period_start)
        """
    )


def _ensure_settings_row(*, tenant_id: str, now_iso: str) -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO tenant_governance_settings (
            tenant_id,
            max_decisions_per_month,
            max_anchors_per_day,
            max_overrides_per_month,
            quota_enforcement_mode,
            security_state,
            security_reason,
            security_since,
            updated_at,
            updated_by
        ) VALUES (?, NULL, NULL, NULL, 'HARD', 'normal', NULL, NULL, ?, 'system')
        ON CONFLICT(tenant_id) DO NOTHING
        """,
        (tenant_id, now_iso),
    )


def _settings_row_to_payload(row: Optional[Dict[str, Any]], *, tenant_id: str) -> Dict[str, Any]:
    payload = {
        "tenant_id": tenant_id,
        "max_decisions_per_month": None,
        "max_anchors_per_day": None,
        "max_overrides_per_month": None,
        "quota_enforcement_mode": "HARD",
        "security_state": "normal",
        "security_reason": None,
        "security_since": None,
        "updated_at": None,
        "updated_by": None,
    }
    if not row:
        return payload
    payload.update(
        {
            "max_decisions_per_month": _normalize_limit(row.get("max_decisions_per_month")),
            "max_anchors_per_day": _normalize_limit(row.get("max_anchors_per_day")),
            "max_overrides_per_month": _normalize_limit(row.get("max_overrides_per_month")),
            "quota_enforcement_mode": _normalize_mode(row.get("quota_enforcement_mode")),
            "security_state": str(row.get("security_state") or "normal").strip().lower() or "normal",
            "security_reason": row.get("security_reason"),
            "security_since": row.get("security_since"),
            "updated_at": row.get("updated_at"),
            "updated_by": row.get("updated_by"),
        }
    )
    return payload


def get_tenant_governance_settings(*, tenant_id: str) -> Dict[str, Any]:
    init_db()
    _ensure_governance_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now_iso = _utc_now().isoformat()
    with storage.transaction():
        _ensure_settings_row(tenant_id=effective_tenant, now_iso=now_iso)
        row = storage.fetchone(
            """
            SELECT tenant_id, max_decisions_per_month, max_anchors_per_day, max_overrides_per_month,
                   quota_enforcement_mode, security_state, security_reason, security_since, updated_at, updated_by
            FROM tenant_governance_settings
            WHERE tenant_id = ?
            LIMIT 1
            """,
            (effective_tenant,),
        )
    return _settings_row_to_payload(row, tenant_id=effective_tenant)


def update_tenant_governance_settings(
    *,
    tenant_id: str,
    max_decisions_per_month: Optional[int] = None,
    max_anchors_per_day: Optional[int] = None,
    max_overrides_per_month: Optional[int] = None,
    quota_enforcement_mode: Optional[str] = None,
    security_state: Optional[str] = None,
    security_reason: Optional[str] = None,
    security_since: Optional[str] = None,
    updated_by: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    _ensure_governance_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now_iso = _utc_now().isoformat()

    with storage.transaction():
        _ensure_settings_row(tenant_id=effective_tenant, now_iso=now_iso)
        current = storage.fetchone(
            """
            SELECT max_decisions_per_month, max_anchors_per_day, max_overrides_per_month,
                   quota_enforcement_mode, security_state, security_reason, security_since
            FROM tenant_governance_settings
            WHERE tenant_id = ?
            LIMIT 1
            """,
            (effective_tenant,),
        ) or {}
        decisions = (
            _normalize_limit(max_decisions_per_month)
            if max_decisions_per_month is not None
            else _normalize_limit(current.get("max_decisions_per_month"))
        )
        anchors = (
            _normalize_limit(max_anchors_per_day)
            if max_anchors_per_day is not None
            else _normalize_limit(current.get("max_anchors_per_day"))
        )
        overrides = (
            _normalize_limit(max_overrides_per_month)
            if max_overrides_per_month is not None
            else _normalize_limit(current.get("max_overrides_per_month"))
        )
        mode = (
            _normalize_mode(quota_enforcement_mode)
            if quota_enforcement_mode is not None
            else _normalize_mode(current.get("quota_enforcement_mode"))
        )
        state = (
            str(security_state).strip().lower()
            if security_state is not None
            else str(current.get("security_state") or "normal").strip().lower()
        ) or "normal"
        reason_value = (
            str(security_reason).strip() or None
            if security_reason is not None
            else (str(current.get("security_reason") or "").strip() or None)
        )
        since_value = (
            str(security_since).strip() or None
            if security_since is not None
            else (str(current.get("security_since") or "").strip() or None)
        )
        storage.execute(
            """
            UPDATE tenant_governance_settings
            SET max_decisions_per_month = ?,
                max_anchors_per_day = ?,
                max_overrides_per_month = ?,
                quota_enforcement_mode = ?,
                security_state = ?,
                security_reason = ?,
                security_since = ?,
                updated_at = ?,
                updated_by = ?
            WHERE tenant_id = ?
            """,
            (
                decisions,
                anchors,
                overrides,
                mode,
                state,
                reason_value,
                since_value,
                now_iso,
                str(updated_by or "system").strip() or "system",
                effective_tenant,
            ),
        )
        row = storage.fetchone(
            """
            SELECT tenant_id, max_decisions_per_month, max_anchors_per_day, max_overrides_per_month,
                   quota_enforcement_mode, security_state, security_reason, security_since, updated_at, updated_by
            FROM tenant_governance_settings
            WHERE tenant_id = ?
            LIMIT 1
            """,
            (effective_tenant,),
        )
    return _settings_row_to_payload(row, tenant_id=effective_tenant)


def _quota_limits_from_settings(settings: Dict[str, Any]) -> TenantQuotaLimits:
    return TenantQuotaLimits(
        max_decisions_per_month=_normalize_limit(settings.get("max_decisions_per_month")),
        max_anchors_per_day=_normalize_limit(settings.get("max_anchors_per_day")),
        max_overrides_per_month=_normalize_limit(settings.get("max_overrides_per_month")),
        quota_enforcement_mode=_normalize_mode(settings.get("quota_enforcement_mode")),
    )


def consume_tenant_quota(
    *,
    tenant_id: str,
    quota_kind: str,
    amount: int = 1,
    enforce_mode: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    init_db()
    _ensure_governance_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    increment = max(1, int(amount))
    now_dt = now or _utc_now()
    now_iso = now_dt.isoformat()

    period_type = _period_type_for_quota(quota_kind)
    period_start = _month_start_iso(now_dt) if period_type == "monthly" else _day_start_iso(now_dt)
    counter_column = _counter_column_for_quota(quota_kind)

    with storage.transaction():
        _ensure_settings_row(tenant_id=effective_tenant, now_iso=now_iso)
        settings = get_tenant_governance_settings(tenant_id=effective_tenant)
        limits = _quota_limits_from_settings(settings)
        limit = _limit_for_quota(limits, quota_kind)

        storage.execute(
            """
            INSERT INTO tenant_usage_counters (
                tenant_id, period_type, period_start,
                decisions_count, anchors_count, overrides_count, updated_at
            ) VALUES (?, ?, ?, 0, 0, 0, ?)
            ON CONFLICT(tenant_id, period_type, period_start) DO NOTHING
            """,
            (effective_tenant, period_type, period_start, now_iso),
        )
        storage.execute(
            f"""
            UPDATE tenant_usage_counters
            SET {counter_column} = {counter_column} + ?,
                updated_at = ?
            WHERE tenant_id = ? AND period_type = ? AND period_start = ?
            """,
            (increment, now_iso, effective_tenant, period_type, period_start),
        )
        usage_row = storage.fetchone(
            f"""
            SELECT decisions_count, anchors_count, overrides_count
            FROM tenant_usage_counters
            WHERE tenant_id = ? AND period_type = ? AND period_start = ?
            LIMIT 1
            """,
            (effective_tenant, period_type, period_start),
        ) or {}
        current_usage = int(usage_row.get(counter_column) or 0)

        hard_enforce = _normalize_mode(enforce_mode or limits.quota_enforcement_mode) != "SOFT"
        exceeded = limit is not None and current_usage > int(limit)
        if exceeded and hard_enforce:
            raise TenantQuotaExceededError(
                tenant_id=effective_tenant,
                quota_name=quota_kind,
                limit=int(limit),
                current_usage=current_usage,
                period_type=period_type,
                period_start=period_start,
            )

    return {
        "tenant_id": effective_tenant,
        "quota": quota_kind,
        "period_type": period_type,
        "period_start": period_start,
        "current_usage": current_usage,
        "limit": limit,
        "exceeded": bool(exceeded),
        "enforced": bool(hard_enforce),
        "quota_warning": bool(exceeded and not hard_enforce),
    }


def get_tenant_governance_metrics(*, tenant_id: str) -> Dict[str, Any]:
    init_db()
    _ensure_governance_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now = _utc_now()
    month_start = _month_start_iso(now)
    day_start = _day_start_iso(now)
    next_month = _next_month_start(now)

    settings = get_tenant_governance_settings(tenant_id=effective_tenant)
    monthly = storage.fetchone(
        """
        SELECT decisions_count, overrides_count
        FROM tenant_usage_counters
        WHERE tenant_id = ? AND period_type = 'monthly' AND period_start = ?
        LIMIT 1
        """,
        (effective_tenant, month_start),
    ) or {}
    daily = storage.fetchone(
        """
        SELECT anchors_count
        FROM tenant_usage_counters
        WHERE tenant_id = ? AND period_type = 'daily' AND period_start = ?
        LIMIT 1
        """,
        (effective_tenant, day_start),
    ) or {}

    denies_row = storage.fetchone(
        """
        SELECT COUNT(1) AS deny_count
        FROM audit_decisions
        WHERE tenant_id = ?
          AND created_at >= ?
          AND created_at < ?
          AND release_status IN ('BLOCKED', 'ERROR')
        """,
        (effective_tenant, month_start, next_month.isoformat()),
    ) or {}

    last_rotation = storage.fetchone(
        """
        SELECT key_id, created_at, rotated_at
        FROM tenant_signing_keys
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (effective_tenant,),
    )

    compromise_rows = storage.fetchall(
        """
        SELECT event_id, revoked_key_id, replacement_key_id, compromise_start, compromise_end, reason, created_at,
               affected_count, affected_attestation_ids_json
        FROM tenant_key_compromise_events
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        LIMIT 20
        """,
        (effective_tenant,),
    )

    state_history = storage.fetchall(
        """
        SELECT event_id, from_state, to_state, reason, source, actor, metadata_json, created_at
        FROM tenant_security_state_events
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        LIMIT 20
        """,
        (effective_tenant,),
    )

    decisions_month = int(monthly.get("decisions_count") or 0)
    denies_month = int(denies_row.get("deny_count") or 0)
    deny_rate = float(denies_month / decisions_month) if decisions_month > 0 else 0.0

    return {
        "tenant_id": effective_tenant,
        "decisions_month": decisions_month,
        "denies_month": denies_month,
        "deny_rate": round(deny_rate, 6),
        "overrides_month": int(monthly.get("overrides_count") or 0),
        "anchors_today": int(daily.get("anchors_count") or 0),
        "security_state": str(settings.get("security_state") or "normal"),
        "security_reason": settings.get("security_reason"),
        "security_since": settings.get("security_since"),
        "last_rotation": {
            "key_id": (last_rotation or {}).get("key_id"),
            "created_at": (last_rotation or {}).get("created_at"),
            "rotated_at": (last_rotation or {}).get("rotated_at"),
        },
        "limits": {
            "max_decisions_per_month": settings.get("max_decisions_per_month"),
            "max_anchors_per_day": settings.get("max_anchors_per_day"),
            "max_overrides_per_month": settings.get("max_overrides_per_month"),
            "quota_enforcement_mode": settings.get("quota_enforcement_mode"),
        },
        "compromise_windows": compromise_rows,
        "lock_history": state_history,
    }
