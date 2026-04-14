from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from releasegate.policy.registry import resolve_registry_policy
from releasegate.policy.simulate_service import _evaluate_effective_policy
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id

DEFAULT_LOOKBACK_DAYS = 30
MAX_LOOKBACK_DAYS = 90
MAX_SIMULATION_ROWS = 20000
DEFAULT_STARTER_PACK = "conservative"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


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


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = _normalize_text(value)
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        if not raw:
            return _utc_now()
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return _utc_now()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_lookback_days(value: Optional[int]) -> int:
    days = int(value or DEFAULT_LOOKBACK_DAYS)
    if days < 1 or days > MAX_LOOKBACK_DAYS:
        raise ValueError(f"lookback_days must be between 1 and {MAX_LOOKBACK_DAYS}")
    return days


def _risk_score(signal_map: Dict[str, Any]) -> Optional[float]:
    if not isinstance(signal_map, dict):
        return None
    risk = signal_map.get("risk")
    if not isinstance(risk, dict):
        return None
    for key in ("score", "risk_score", "value"):
        raw = risk.get(key)
        if isinstance(raw, (int, float)):
            score = float(raw)
            if score > 1.0 and score <= 100.0:
                score = score / 100.0
            return min(1.0, max(0.0, score))
    level = _normalize_text(risk.get("level")).lower()
    if level == "high":
        return 0.85
    if level == "medium":
        return 0.5
    if level == "low":
        return 0.2
    return None


def _risk_bucket(score: Optional[float]) -> str:
    if score is None:
        return "low"
    if score >= 0.7:
        return "high"
    if score >= 0.3:
        return "medium"
    return "low"


def _fetch_historical_rows(
    *,
    tenant_id: str,
    start_ts: datetime,
    end_ts: datetime,
) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    params = (
        tenant_id,
        start_ts.isoformat(),
        end_ts.isoformat(),
        MAX_SIMULATION_ROWS,
    )
    query_with_linkage = """
        SELECT
            d.decision_id,
            d.created_at,
            d.full_decision_json,
            l.jira_issue_id AS link_issue_key,
            l.transition_id AS link_transition_id,
            l.actor AS link_actor
        FROM audit_decisions d
        LEFT JOIN decision_transition_links l
          ON d.tenant_id = l.tenant_id
         AND d.decision_id = l.decision_id
        WHERE d.tenant_id = ?
          AND d.created_at >= ?
          AND d.created_at <= ?
        ORDER BY d.created_at DESC
        LIMIT ?
    """
    try:
        return storage.fetchall(query_with_linkage, params)
    except Exception:
        return storage.fetchall(
            """
            SELECT decision_id, created_at, full_decision_json
            FROM audit_decisions
            WHERE tenant_id = ?
              AND created_at >= ?
              AND created_at <= ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            params,
        )


def _extract_event(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    payload = _parse_json(row.get("full_decision_json"), {})
    input_snapshot = _parse_json(payload.get("input_snapshot"), {})
    request = _parse_json(input_snapshot.get("request"), {})
    signal_map = _parse_json(input_snapshot.get("signal_map"), {})
    context_overrides = _parse_json(request.get("context_overrides"), {})

    transition_id = _normalize_text(row.get("link_transition_id")) or _normalize_text(request.get("transition_id"))
    if not transition_id:
        return None

    risk_score = _risk_score(signal_map)
    created_at = _parse_timestamp(row.get("created_at")).isoformat()
    return {
        "decision_id": _normalize_text(row.get("decision_id")),
        "issue_key": _normalize_text(row.get("link_issue_key")) or _normalize_text(request.get("issue_key")),
        "transition_id": transition_id,
        "project_key": _normalize_text(request.get("project_key")) or None,
        "workflow_id": _normalize_text(context_overrides.get("workflow_id")) or _normalize_text(request.get("transition_name")) or None,
        "environment": _normalize_text(request.get("environment")) or None,
        "actor": _normalize_text(row.get("link_actor")) or _normalize_text(request.get("actor_account_id")) or None,
        "risk_bucket": _risk_bucket(risk_score),
        "signal_map": signal_map,
        "created_at": created_at,
    }


def _approvals_missing(signal_map: Dict[str, Any]) -> bool:
    if not isinstance(signal_map, dict):
        return False

    approvals = signal_map.get("approvals")
    if isinstance(approvals, dict):
        required = approvals.get("required")
        satisfied = approvals.get("satisfied")
        if required is not None or satisfied is not None:
            return bool(required) and not bool(satisfied)

    required = signal_map.get("approvals.required")
    satisfied = signal_map.get("approvals.satisfied")
    if required is None and satisfied is None:
        return False
    return bool(required) and not bool(satisfied)


def _build_summary(*, total_transitions: int, insights: Dict[str, int]) -> Optional[str]:
    if total_transitions <= 0:
        return "No recent release decisions were available yet. Connect Jira and complete a few transitions to generate your first risk snapshot."

    findings: List[str] = []
    high_risk = int(insights.get("high_risk_releases") or 0)
    missing_approvals = int(insights.get("missing_approvals") or 0)
    unmapped_transitions = int(insights.get("unmapped_transitions") or 0)

    if high_risk:
        findings.append(f"{high_risk} looked high risk")
    if missing_approvals:
        findings.append(f"{missing_approvals} were missing approvals")
    if unmapped_transitions:
        findings.append(f"{unmapped_transitions} had no mapped protection")

    if not findings:
        return f"We analyzed your last {total_transitions} releases and found a clean baseline under the starter checks."

    return f"We analyzed your last {total_transitions} releases. " + "; ".join(findings) + "."


def _evaluate_event(*, tenant_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
    transition_id = _normalize_text(event.get("transition_id"))
    if not transition_id:
        return {
            "allow": True,
            "has_policy": False,
            "starter_pack_blocked": False,
            "missing_approvals": False,
            "high_risk": False,
        }
    resolved = resolve_registry_policy(
        tenant_id=tenant_id,
        org_id=tenant_id,
        project_id=event.get("project_key"),
        workflow_id=event.get("workflow_id"),
        transition_id=transition_id,
        rollout_key=event.get("issue_key") or event.get("decision_id") or transition_id,
        status_filter="ACTIVE",
    )
    effective_policy = (
        resolved.get("effective_policy")
        if isinstance(resolved.get("effective_policy"), dict)
        else {}
    )
    has_policy = bool(effective_policy)
    decision = _evaluate_effective_policy(
        effective_policy=effective_policy,
        transition_id=transition_id,
        project_id=event.get("project_key"),
        workflow_id=event.get("workflow_id"),
        environment=event.get("environment"),
    )
    registry_allow = bool(decision.get("allow"))
    high_risk = str(event.get("risk_bucket") or "").lower() == "high"
    missing_approvals = _approvals_missing(event.get("signal_map") if isinstance(event.get("signal_map"), dict) else {})
    starter_pack_blocked = high_risk or missing_approvals
    return {
        "allow": bool(registry_allow and not starter_pack_blocked),
        "has_policy": has_policy,
        "starter_pack_blocked": starter_pack_blocked,
        "missing_approvals": missing_approvals,
        "high_risk": high_risk,
    }


def _zero_result(*, tenant_id: str, lookback_days: int, has_run: bool, ran_at: Optional[str]) -> Dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "lookback_days": int(lookback_days),
        "total_transitions": 0,
        "allowed": 0,
        "blocked": 0,
        "blocked_pct": 0.0,
        "override_required": 0,
        "starter_pack": DEFAULT_STARTER_PACK,
        "insights": {
            "high_risk_releases": 0,
            "missing_approvals": 0,
            "unmapped_transitions": 0,
        },
        "summary": _build_summary(
            total_transitions=0,
            insights={
                "high_risk_releases": 0,
                "missing_approvals": 0,
                "unmapped_transitions": 0,
            },
        ),
        "risk_distribution": {"low": 0, "medium": 0, "high": 0},
        "ran_at": ran_at,
        "has_run": bool(has_run),
    }


def run_historical_simulation(
    *,
    tenant_id: Optional[str],
    lookback_days: Optional[int] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_lookback = _normalize_lookback_days(lookback_days)

    end_ts = _utc_now()
    start_ts = end_ts - timedelta(days=normalized_lookback)
    rows = _fetch_historical_rows(
        tenant_id=effective_tenant,
        start_ts=start_ts,
        end_ts=end_ts,
    )

    total_transitions = 0
    allowed = 0
    blocked = 0
    risk_distribution = {"low": 0, "medium": 0, "high": 0}
    insights = {
        "high_risk_releases": 0,
        "missing_approvals": 0,
        "unmapped_transitions": 0,
    }

    for row in rows:
        event = _extract_event(row)
        if not event:
            continue
        total_transitions += 1
        risk_key = str(event.get("risk_bucket") or "low").lower()
        if risk_key not in risk_distribution:
            risk_key = "low"
        risk_distribution[risk_key] += 1
        evaluation = _evaluate_event(tenant_id=effective_tenant, event=event)
        if evaluation.get("high_risk"):
            insights["high_risk_releases"] += 1
        if evaluation.get("missing_approvals"):
            insights["missing_approvals"] += 1
        if not evaluation.get("has_policy", False):
            insights["unmapped_transitions"] += 1
        if evaluation.get("allow"):
            allowed += 1
        else:
            blocked += 1

    blocked_pct = 0.0
    if total_transitions > 0:
        blocked_pct = round((float(blocked) / float(total_transitions)) * 100.0, 2)

    ran_at = _utc_now().isoformat()
    result = {
        "tenant_id": effective_tenant,
        "lookback_days": normalized_lookback,
        "total_transitions": int(total_transitions),
        "allowed": int(allowed),
        "blocked": int(blocked),
        "blocked_pct": float(blocked_pct),
        "override_required": int(blocked),
        "starter_pack": DEFAULT_STARTER_PACK,
        "insights": insights,
        "summary": _build_summary(total_transitions=total_transitions, insights=insights),
        "risk_distribution": risk_distribution,
        "ran_at": ran_at,
        "has_run": True,
    }

    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO tenant_simulation_runs (
            tenant_id,
            run_id,
            lookback_days,
            result_json,
            ran_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            str(uuid.uuid4()),
            normalized_lookback,
            json.dumps(result, separators=(",", ":"), sort_keys=True, ensure_ascii=False),
            ran_at,
        ),
    )
    return result


def get_last_historical_simulation(
    *,
    tenant_id: Optional[str],
    lookback_days: Optional[int] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_lookback = _normalize_lookback_days(lookback_days)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT result_json
        FROM tenant_simulation_runs
        WHERE tenant_id = ?
          AND lookback_days = ?
        ORDER BY ran_at DESC
        LIMIT 1
        """,
        (effective_tenant, normalized_lookback),
    )
    if not row:
        return _zero_result(
            tenant_id=effective_tenant,
            lookback_days=normalized_lookback,
            has_run=False,
            ran_at=None,
        )

    result = _parse_json(row.get("result_json"), {})
    if not isinstance(result, dict):
        return _zero_result(
            tenant_id=effective_tenant,
            lookback_days=normalized_lookback,
            has_run=False,
            ran_at=None,
        )
    payload = _zero_result(
        tenant_id=effective_tenant,
        lookback_days=normalized_lookback,
        has_run=True,
        ran_at=_normalize_text(result.get("ran_at")) or None,
    )
    payload.update(
        {
            "total_transitions": int(result.get("total_transitions") or 0),
            "allowed": int(result.get("allowed") or 0),
            "blocked": int(result.get("blocked") or 0),
            "blocked_pct": float(result.get("blocked_pct") or 0.0),
            "override_required": int(result.get("override_required") or 0),
            "starter_pack": _normalize_text(result.get("starter_pack")) or DEFAULT_STARTER_PACK,
            "insights": {
                "high_risk_releases": int(((result.get("insights") or {}).get("high_risk_releases")) or 0),
                "missing_approvals": int(((result.get("insights") or {}).get("missing_approvals")) or 0),
                "unmapped_transitions": int(((result.get("insights") or {}).get("unmapped_transitions")) or 0),
            },
            "summary": _normalize_text(result.get("summary")) or _build_summary(
                total_transitions=int(result.get("total_transitions") or 0),
                insights={
                    "high_risk_releases": int(((result.get("insights") or {}).get("high_risk_releases")) or 0),
                    "missing_approvals": int(((result.get("insights") or {}).get("missing_approvals")) or 0),
                    "unmapped_transitions": int(((result.get("insights") or {}).get("unmapped_transitions")) or 0),
                },
            ),
            "risk_distribution": {
                "low": int(((result.get("risk_distribution") or {}).get("low")) or 0),
                "medium": int(((result.get("risk_distribution") or {}).get("medium")) or 0),
                "high": int(((result.get("risk_distribution") or {}).get("high")) or 0),
            },
            "ran_at": _normalize_text(result.get("ran_at")) or None,
            "has_run": bool(result.get("has_run", True)),
        }
    )
    return payload
