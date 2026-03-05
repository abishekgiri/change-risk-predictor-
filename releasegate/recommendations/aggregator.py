from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional
import hashlib

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json


STRICT_FAIL_CLOSED_CODES = {
    "POLICY_NOT_LOADED",
    "POLICY_RELEASE_MISSING",
    "PROVIDER_TIMEOUT",
    "PROVIDER_ERROR",
    "SYSTEM_FAILURE",
}

SIGNAL_MISSING_CODES = {
    "SIGNAL_STALE",
    "STALE_SIGNAL",
    "RISK_SIGNAL_MISSING",
    "RISK_SIGNAL_EXPIRED",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _parse_json(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(value, dict):
            return value
    return {}


def _parse_datetime(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        dt = raw
    else:
        text = str(raw).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _bucket_increment(counter: Dict[str, int], key: Optional[str], amount: int = 1) -> None:
    normalized = str(key or "unknown").strip() or "unknown"
    counter[normalized] = int(counter.get(normalized) or 0) + int(amount)


def aggregate_governance_signals(
    *,
    tenant_id: Optional[str],
    lookback_days: int = 30,
    as_of: Optional[datetime] = None,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_lookback = max(1, min(int(lookback_days or 30), 365))
    now = as_of.astimezone(timezone.utc) if isinstance(as_of, datetime) else _utc_now()
    from_dt = now - timedelta(days=bounded_lookback)

    storage = get_storage_backend()
    decision_rows = storage.fetchall(
        """
        SELECT decision_id, release_status, full_decision_json, policy_hash, created_at
        FROM audit_decisions
        WHERE tenant_id = ? AND created_at >= ?
        ORDER BY created_at ASC
        """,
        (effective_tenant, from_dt.isoformat()),
    )
    override_rows = storage.fetchall(
        """
        SELECT override_id, repo, actor, created_at
        FROM audit_overrides
        WHERE tenant_id = ? AND created_at >= ?
        ORDER BY created_at ASC
        """,
        (effective_tenant, from_dt.isoformat()),
    )

    total_decisions = 0
    blocked_decisions = 0
    missing_signals: Dict[str, int] = {}
    strict_fail_closed_counts: Dict[str, int] = {}
    deny_rate_by_reason: Dict[str, int] = {}
    policy_hashes: set[str] = set()
    project_decision_counts: Dict[str, int] = {}

    for row in decision_rows:
        total_decisions += 1
        payload = _parse_json(row.get("full_decision_json"))
        reason_code = str(payload.get("reason_code") or "").strip() or "UNKNOWN"
        release_status = str(row.get("release_status") or "").strip().upper()
        policy_hash = str(row.get("policy_hash") or "").strip()
        if policy_hash:
            policy_hashes.add(policy_hash)

        project_key = (
            str(payload.get("project_key") or "").strip()
            or str(((payload.get("input_snapshot") or {}).get("project_key") or "")).strip()
            or str(payload.get("repo") or row.get("repo") or "").strip()
            or "unknown"
        )
        _bucket_increment(project_decision_counts, project_key)

        if release_status not in {"ALLOWED", "ALLOW"}:
            blocked_decisions += 1
            _bucket_increment(deny_rate_by_reason, reason_code)
        if reason_code in SIGNAL_MISSING_CODES:
            _bucket_increment(missing_signals, reason_code)
        if reason_code in STRICT_FAIL_CLOSED_CODES:
            _bucket_increment(strict_fail_closed_counts, reason_code)

    override_rate_by_project: Dict[str, float] = {}
    override_counts_by_project: Dict[str, int] = {}
    override_actor_counts: Dict[str, int] = {}
    for row in override_rows:
        project = str(row.get("repo") or "unknown").strip() or "unknown"
        actor = str(row.get("actor") or "unknown").strip() or "unknown"
        _bucket_increment(override_counts_by_project, project)
        _bucket_increment(override_actor_counts, actor)
    for project, override_count in override_counts_by_project.items():
        denominator = int(project_decision_counts.get(project) or 0)
        override_rate_by_project[project] = float(override_count / denominator) if denominator > 0 else float(override_count)

    insight_date = now.date().isoformat()
    payload = {
        "tenant_id": effective_tenant,
        "lookback_days": bounded_lookback,
        "insight_date_utc": insight_date,
        "generated_at": now.isoformat(),
        "totals": {
            "decision_count": total_decisions,
            "blocked_count": blocked_decisions,
            "override_count": len(override_rows),
            "blocked_rate": float(blocked_decisions / total_decisions) if total_decisions > 0 else 0.0,
        },
        "override_rate_by_project": override_rate_by_project,
        "override_counts_by_project": override_counts_by_project,
        "override_actor_counts": override_actor_counts,
        "deny_rate_by_reason": deny_rate_by_reason,
        "missing_signal_counts": missing_signals,
        "strict_fail_closed_trigger_counts": strict_fail_closed_counts,
        "policy_change_count": max(0, len(policy_hashes) - 1),
    }
    return payload


def persist_governance_insight(
    *,
    tenant_id: Optional[str],
    insight_payload: Dict[str, Any],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id or insight_payload.get("tenant_id"))
    insight_date = str(insight_payload.get("insight_date_utc") or _utc_now().date().isoformat())
    lookback_days = max(1, min(int(insight_payload.get("lookback_days") or 30), 365))
    insight_id = f"ins_{hashlib.sha256(f'{effective_tenant}:{insight_date}:{lookback_days}'.encode('utf-8')).hexdigest()[:24]}"
    created_at = _utc_now_iso()

    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO governance_insights (
            tenant_id,
            insight_id,
            insight_date_utc,
            lookback_days,
            override_rate_by_project_json,
            deny_rate_by_reason_json,
            missing_signal_counts_json,
            strict_fail_closed_trigger_counts_json,
            metadata_json,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, insight_id) DO UPDATE SET
            override_rate_by_project_json = excluded.override_rate_by_project_json,
            deny_rate_by_reason_json = excluded.deny_rate_by_reason_json,
            missing_signal_counts_json = excluded.missing_signal_counts_json,
            strict_fail_closed_trigger_counts_json = excluded.strict_fail_closed_trigger_counts_json,
            metadata_json = excluded.metadata_json,
            created_at = excluded.created_at
        """,
        (
            effective_tenant,
            insight_id,
            insight_date,
            lookback_days,
            canonical_json(insight_payload.get("override_rate_by_project") or {}),
            canonical_json(insight_payload.get("deny_rate_by_reason") or {}),
            canonical_json(insight_payload.get("missing_signal_counts") or {}),
            canonical_json(insight_payload.get("strict_fail_closed_trigger_counts") or {}),
            canonical_json(
                {
                    "totals": insight_payload.get("totals") or {},
                    "policy_change_count": int(insight_payload.get("policy_change_count") or 0),
                    "override_counts_by_project": insight_payload.get("override_counts_by_project") or {},
                    "override_actor_counts": insight_payload.get("override_actor_counts") or {},
                    "generated_at": insight_payload.get("generated_at"),
                }
            ),
            created_at,
        ),
    )
    return load_latest_governance_insight(tenant_id=effective_tenant) or {}


def _row_to_insight(row: Dict[str, Any]) -> Dict[str, Any]:
    metadata = _parse_json(row.get("metadata_json"))
    return {
        "tenant_id": row.get("tenant_id"),
        "insight_id": row.get("insight_id"),
        "insight_date_utc": row.get("insight_date_utc"),
        "lookback_days": int(row.get("lookback_days") or 0),
        "override_rate_by_project": _parse_json(row.get("override_rate_by_project_json")),
        "deny_rate_by_reason": _parse_json(row.get("deny_rate_by_reason_json")),
        "missing_signal_counts": _parse_json(row.get("missing_signal_counts_json")),
        "strict_fail_closed_trigger_counts": _parse_json(row.get("strict_fail_closed_trigger_counts_json")),
        "totals": metadata.get("totals") if isinstance(metadata.get("totals"), dict) else {},
        "policy_change_count": int(metadata.get("policy_change_count") or 0),
        "override_counts_by_project": (
            metadata.get("override_counts_by_project")
            if isinstance(metadata.get("override_counts_by_project"), dict)
            else {}
        ),
        "override_actor_counts": (
            metadata.get("override_actor_counts")
            if isinstance(metadata.get("override_actor_counts"), dict)
            else {}
        ),
        "generated_at": metadata.get("generated_at"),
        "created_at": row.get("created_at"),
    }


def load_latest_governance_insight(*, tenant_id: Optional[str]) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, insight_id, insight_date_utc, lookback_days,
               override_rate_by_project_json, deny_rate_by_reason_json, missing_signal_counts_json,
               strict_fail_closed_trigger_counts_json, metadata_json, created_at
        FROM governance_insights
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (effective_tenant,),
    )
    if not row:
        return None
    return _row_to_insight(row)


def top_items(mapping: Dict[str, Any], *, limit: int = 5) -> Dict[str, Any]:
    items: list[tuple[str, float]] = []
    for key, value in mapping.items():
        try:
            numeric = float(value)
        except Exception:
            continue
        items.append((str(key), numeric))
    items.sort(key=lambda item: item[1], reverse=True)
    return {key: value for key, value in items[: max(1, int(limit))]}
