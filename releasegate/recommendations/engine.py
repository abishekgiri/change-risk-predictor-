from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.recommendations.aggregator import (
    aggregate_governance_signals,
    load_latest_governance_insight,
    persist_governance_insight,
    top_items,
)
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json


OPEN_STATUSES = {"OPEN", "ACKED", "RESOLVED"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_status(status: Optional[str]) -> str:
    value = str(status or "OPEN").strip().upper()
    if value not in OPEN_STATUSES:
        return "OPEN"
    return value


def _recommendation_id(tenant_id: str, fingerprint: str) -> str:
    digest = hashlib.sha256(f"{tenant_id}:{fingerprint}".encode("utf-8")).hexdigest()
    return f"reco_{digest[:24]}"


def _make_recommendation(
    *,
    recommendation_type: str,
    severity: str,
    title: str,
    message: str,
    playbook: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    fingerprint = hashlib.sha256(
        canonical_json(
            {
                "type": recommendation_type,
                "title": title,
                "playbook": playbook,
                "context": context,
            }
        ).encode("utf-8")
    ).hexdigest()
    return {
        "recommendation_type": recommendation_type,
        "severity": str(severity).upper(),
        "status": "OPEN",
        "title": title,
        "message": message,
        "playbook": playbook,
        "fingerprint": fingerprint,
        "context": context,
    }


def _derive_recommendations(insight: Dict[str, Any]) -> List[Dict[str, Any]]:
    recommendations: List[Dict[str, Any]] = []
    totals = insight.get("totals") if isinstance(insight.get("totals"), dict) else {}
    decision_count = int(totals.get("decision_count") or 0)
    override_count = int(totals.get("override_count") or 0)

    override_actors = insight.get("override_actor_counts") if isinstance(insight.get("override_actor_counts"), dict) else {}
    top_override_actors = top_items(override_actors, limit=3)
    top_override_total = sum(int(value) for value in top_override_actors.values())
    concentration = float(top_override_total / override_count) if override_count > 0 else 0.0
    if override_count >= 5 and concentration >= 0.6:
        recommendations.append(
            _make_recommendation(
                recommendation_type="OVERRIDE_SPIKE",
                severity="HIGH",
                title="Override concentration risk",
                message=(
                    f"Top actors account for {concentration:.1%} of overrides in the active window. "
                    "This indicates concentrated bypass behavior."
                ),
                playbook="Require dual-approval for overrides in affected projects and review role assignments.",
                context={
                    "concentration_index": concentration,
                    "override_count": override_count,
                    "top_override_actors": top_override_actors,
                },
            )
        )

    missing_signals = insight.get("missing_signal_counts") if isinstance(insight.get("missing_signal_counts"), dict) else {}
    missing_signal_total = sum(int(value) for value in missing_signals.values())
    if missing_signal_total >= 3:
        recommendations.append(
            _make_recommendation(
                recommendation_type="MISSING_SIGNALS",
                severity="MEDIUM",
                title="Signal freshness/control drift",
                message=(
                    f"{missing_signal_total} decisions were blocked due to missing or stale governance signals."
                ),
                playbook="Validate signal ingestion jobs and tighten TTL alerts for risk-eval sources.",
                context={
                    "missing_signal_total": missing_signal_total,
                    "missing_signal_breakdown": top_items(missing_signals, limit=5),
                },
            )
        )

    strict_fail_closed = (
        insight.get("strict_fail_closed_trigger_counts")
        if isinstance(insight.get("strict_fail_closed_trigger_counts"), dict)
        else {}
    )
    strict_fail_closed_total = sum(int(value) for value in strict_fail_closed.values())
    if strict_fail_closed_total > 0:
        recommendations.append(
            _make_recommendation(
                recommendation_type="STRICT_FAIL_CLOSED_SPIKE",
                severity="HIGH",
                title="Strict fail-closed events detected",
                message=(
                    f"{strict_fail_closed_total} gate evaluations hit strict fail-closed pathways."
                ),
                playbook="Investigate policy resolution/provider health before enabling stricter rollout stages.",
                context={
                    "strict_fail_closed_total": strict_fail_closed_total,
                    "strict_fail_closed_breakdown": top_items(strict_fail_closed, limit=5),
                },
            )
        )

    policy_change_count = int(insight.get("policy_change_count") or 0)
    blocked_rate = float(totals.get("blocked_rate") or 0.0)
    if policy_change_count > 0 and decision_count >= 10 and blocked_rate >= 0.2:
        recommendations.append(
            _make_recommendation(
                recommendation_type="POLICY_DRIFT",
                severity="MEDIUM",
                title="Policy drift after changes",
                message=(
                    f"Blocked decision rate is {blocked_rate:.1%} with {policy_change_count} policy-hash changes in window."
                ),
                playbook="Run policy simulation against last 30 days and consider staged rollback/canary rollout.",
                context={
                    "blocked_rate": blocked_rate,
                    "policy_change_count": policy_change_count,
                },
            )
        )

    return recommendations


def upsert_recommendations(
    *,
    tenant_id: Optional[str],
    recommendations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    now = _utc_now_iso()
    rows: List[Dict[str, Any]] = []

    for recommendation in recommendations:
        fingerprint = str(recommendation.get("fingerprint") or "").strip()
        if not fingerprint:
            continue
        recommendation_id = _recommendation_id(effective_tenant, fingerprint)
        existing = storage.fetchone(
            """
            SELECT tenant_id, recommendation_id, recommendation_type, severity, status, title, message,
                   playbook, fingerprint, context_json, acked_by, acked_at, created_at, updated_at
            FROM governance_recommendations
            WHERE tenant_id = ? AND recommendation_id = ?
            LIMIT 1
            """,
            (effective_tenant, recommendation_id),
        )
        if existing:
            status = _normalize_status(existing.get("status"))
            acked_by = existing.get("acked_by")
            acked_at = existing.get("acked_at")
            storage.execute(
                """
                UPDATE governance_recommendations
                SET recommendation_type = ?,
                    severity = ?,
                    status = ?,
                    title = ?,
                    message = ?,
                    playbook = ?,
                    fingerprint = ?,
                    context_json = ?,
                    acked_by = ?,
                    acked_at = ?,
                    updated_at = ?
                WHERE tenant_id = ? AND recommendation_id = ?
                """,
                (
                    str(recommendation.get("recommendation_type") or "UNKNOWN"),
                    str(recommendation.get("severity") or "LOW").upper(),
                    status,
                    str(recommendation.get("title") or ""),
                    str(recommendation.get("message") or ""),
                    str(recommendation.get("playbook") or ""),
                    fingerprint,
                    canonical_json(recommendation.get("context") or {}),
                    acked_by,
                    acked_at,
                    now,
                    effective_tenant,
                    recommendation_id,
                ),
            )
        else:
            storage.execute(
                """
                INSERT INTO governance_recommendations (
                    tenant_id, recommendation_id, recommendation_type, severity, status,
                    title, message, playbook, fingerprint, context_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    effective_tenant,
                    recommendation_id,
                    str(recommendation.get("recommendation_type") or "UNKNOWN"),
                    str(recommendation.get("severity") or "LOW").upper(),
                    "OPEN",
                    str(recommendation.get("title") or ""),
                    str(recommendation.get("message") or ""),
                    str(recommendation.get("playbook") or ""),
                    fingerprint,
                    canonical_json(recommendation.get("context") or {}),
                    now,
                    now,
                ),
            )
        row = storage.fetchone(
            """
            SELECT tenant_id, recommendation_id, recommendation_type, severity, status, title, message,
                   playbook, fingerprint, context_json, acked_by, acked_at, created_at, updated_at
            FROM governance_recommendations
            WHERE tenant_id = ? AND recommendation_id = ?
            LIMIT 1
            """,
            (effective_tenant, recommendation_id),
        )
        if row:
            rows.append(_row_to_recommendation(row))
    return rows


def _row_to_recommendation(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tenant_id": row.get("tenant_id"),
        "recommendation_id": row.get("recommendation_id"),
        "recommendation_type": row.get("recommendation_type"),
        "severity": row.get("severity"),
        "status": row.get("status"),
        "title": row.get("title"),
        "message": row.get("message"),
        "playbook": row.get("playbook"),
        "fingerprint": row.get("fingerprint"),
        "context": json.loads(row.get("context_json") or "{}"),
        "acked_by": row.get("acked_by"),
        "acked_at": row.get("acked_at"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def list_recommendations(
    *,
    tenant_id: Optional[str],
    status: Optional[str] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    bounded_limit = max(1, min(int(limit or 25), 200))
    storage = get_storage_backend()
    normalized_status = str(status or "").strip().upper()
    if normalized_status:
        rows = storage.fetchall(
            """
            SELECT tenant_id, recommendation_id, recommendation_type, severity, status, title, message,
                   playbook, fingerprint, context_json, acked_by, acked_at, created_at, updated_at
            FROM governance_recommendations
            WHERE tenant_id = ? AND status = ?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (effective_tenant, normalized_status, bounded_limit),
        )
    else:
        rows = storage.fetchall(
            """
            SELECT tenant_id, recommendation_id, recommendation_type, severity, status, title, message,
                   playbook, fingerprint, context_json, acked_by, acked_at, created_at, updated_at
            FROM governance_recommendations
            WHERE tenant_id = ?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (effective_tenant, bounded_limit),
        )
    return [_row_to_recommendation(row) for row in rows]


def acknowledge_recommendation(
    *,
    tenant_id: Optional[str],
    recommendation_id: str,
    actor_id: str,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_id = str(recommendation_id or "").strip()
    if not normalized_id:
        raise ValueError("recommendation_id is required")
    normalized_actor = str(actor_id or "").strip() or "unknown"
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, recommendation_id, recommendation_type, severity, status, title, message,
               playbook, fingerprint, context_json, acked_by, acked_at, created_at, updated_at
        FROM governance_recommendations
        WHERE tenant_id = ? AND recommendation_id = ?
        LIMIT 1
        """,
        (effective_tenant, normalized_id),
    )
    if not row:
        raise ValueError("recommendation not found")
    now = _utc_now_iso()
    storage.execute(
        """
        UPDATE governance_recommendations
        SET status = 'ACKED',
            acked_by = ?,
            acked_at = ?,
            updated_at = ?
        WHERE tenant_id = ? AND recommendation_id = ?
        """,
        (normalized_actor, now, now, effective_tenant, normalized_id),
    )
    updated = storage.fetchone(
        """
        SELECT tenant_id, recommendation_id, recommendation_type, severity, status, title, message,
               playbook, fingerprint, context_json, acked_by, acked_at, created_at, updated_at
        FROM governance_recommendations
        WHERE tenant_id = ? AND recommendation_id = ?
        LIMIT 1
        """,
        (effective_tenant, normalized_id),
    )
    if not updated:
        raise RuntimeError("failed to persist recommendation acknowledgement")
    return _row_to_recommendation(updated)


def generate_recommendations(
    *,
    tenant_id: Optional[str],
    lookback_days: int = 30,
    persist: bool = True,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    insight_payload = aggregate_governance_signals(
        tenant_id=effective_tenant,
        lookback_days=lookback_days,
    )
    if persist:
        persisted = persist_governance_insight(
            tenant_id=effective_tenant,
            insight_payload=insight_payload,
        )
        if persisted:
            insight_payload = persisted
    recommendations = _derive_recommendations(insight_payload)
    stored = upsert_recommendations(
        tenant_id=effective_tenant,
        recommendations=recommendations,
    )
    return {
        "tenant_id": effective_tenant,
        "generated_at": _utc_now_iso(),
        "lookback_days": max(1, min(int(lookback_days or 30), 365)),
        "insight": insight_payload,
        "recommendations": stored,
    }


def get_or_generate_recommendations(
    *,
    tenant_id: Optional[str],
    lookback_days: int = 30,
    force_refresh: bool = False,
    status: Optional[str] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    latest_insight = load_latest_governance_insight(tenant_id=effective_tenant)
    if force_refresh or latest_insight is None:
        generated = generate_recommendations(
            tenant_id=effective_tenant,
            lookback_days=lookback_days,
            persist=True,
        )
        recommendations = generated.get("recommendations") if isinstance(generated.get("recommendations"), list) else []
        return {
            "tenant_id": effective_tenant,
            "generated_at": generated.get("generated_at"),
            "lookback_days": int(generated.get("lookback_days") or lookback_days),
            "insight": generated.get("insight") if isinstance(generated.get("insight"), dict) else {},
            "recommendations": recommendations[: max(1, min(int(limit or 25), 200))],
        }

    recommendations = list_recommendations(
        tenant_id=effective_tenant,
        status=status,
        limit=limit,
    )
    return {
        "tenant_id": effective_tenant,
        "generated_at": latest_insight.get("generated_at") or latest_insight.get("created_at"),
        "lookback_days": int(latest_insight.get("lookback_days") or lookback_days),
        "insight": latest_insight,
        "recommendations": recommendations,
    }
