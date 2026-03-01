from __future__ import annotations

import json
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from releasegate.policy.registry import get_registry_policy
from releasegate.policy.simulate_service import _evaluate_effective_policy
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


_WINDOW_CHOICES = {30, 60, 90}
_MAX_EVENTS_HARD_CAP = 50000
_DEFAULT_MAX_EVENTS = 10000
_DEFAULT_TOP_N = 10


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _parse_json(value: Any, fallback: Any) -> Any:
    if isinstance(value, type(fallback)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return fallback
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, type(fallback)):
                return parsed
        except json.JSONDecodeError:
            return fallback
    return fallback


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        raw = _normalize_text(value)
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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
            if score < 0.0:
                score = 0.0
            if score > 1.0:
                score = 1.0
            return score
    level = _normalize_lower(risk.get("level"))
    if level == "low":
        return 0.2
    if level == "medium":
        return 0.5
    if level == "high":
        return 0.85
    if level == "critical":
        return 0.95
    return None


def _risk_bucket(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 0.7:
        return "high"
    if score >= 0.3:
        return "medium"
    return "low"


def _is_protected_status(status: str) -> bool:
    from releasegate.integrations.jira.decision_linkage import is_protected_status

    return bool(is_protected_status(status))


def _policy_by_id_and_version(*, tenant_id: str, policy_id: str, version: int) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, policy_id, version, status, policy_hash, policy_json
        FROM policy_registry_entries
        WHERE tenant_id = ? AND policy_id = ? AND version = ?
        LIMIT 1
        """,
        (tenant_id, _normalize_text(policy_id), int(version)),
    )
    if not row:
        return None
    return {
        "tenant_id": row.get("tenant_id"),
        "policy_id": row.get("policy_id"),
        "version": int(row.get("version") or 0),
        "status": _normalize_text(row.get("status")),
        "policy_hash": _normalize_text(row.get("policy_hash")),
        "policy_json": _parse_json(row.get("policy_json"), {}),
    }


def _resolve_candidate_policy(
    *,
    tenant_id: str,
    policy_id: Optional[str],
    policy_version: Optional[int],
    policy_json: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if isinstance(policy_json, dict) and policy_json:
        normalized = json.loads(canonical_json(policy_json))
        return {
            "policy_id": _normalize_text(policy_id) or "explicit",
            "policy_version": int(policy_version or 0) if policy_version is not None else None,
            "policy_hash": sha256_json(normalized),
            "policy_json": normalized,
            "source": "explicit",
        }

    candidate_id = _normalize_text(policy_id)
    if not candidate_id:
        raise ValueError("policy_id or policy_json is required")

    selected: Optional[Dict[str, Any]]
    if policy_version is not None:
        selected = _policy_by_id_and_version(
            tenant_id=tenant_id,
            policy_id=candidate_id,
            version=int(policy_version),
        )
        if not selected:
            raise ValueError("candidate policy version not found")
        source = "registry_version"
    else:
        selected = get_registry_policy(tenant_id=tenant_id, policy_id=candidate_id)
        if not selected:
            raise ValueError("candidate policy not found")
        source = "registry_latest"

    payload = selected.get("policy_json") if isinstance(selected.get("policy_json"), dict) else {}
    normalized = json.loads(canonical_json(payload))
    return {
        "policy_id": _normalize_text(selected.get("policy_id")) or candidate_id,
        "policy_version": int(selected.get("version") or 0) if selected.get("version") is not None else None,
        "policy_hash": _normalize_text(selected.get("policy_hash")) or sha256_json(normalized),
        "policy_json": normalized,
        "source": source,
    }


def _fetch_historical_rows(
    *,
    tenant_id: str,
    window_start: datetime,
    window_end: datetime,
    max_events: int,
) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    params = (
        tenant_id,
        window_start.isoformat(),
        window_end.isoformat(),
        int(max_events) + 1,
    )
    query_with_linkage = """
        SELECT
            d.decision_id,
            d.created_at,
            d.release_status,
            d.full_decision_json,
            l.jira_issue_id AS link_issue_key,
            l.transition_id AS link_transition_id,
            l.actor AS link_actor,
            l.source_status AS link_source_status,
            l.target_status AS link_target_status
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
            SELECT decision_id, created_at, release_status, full_decision_json
            FROM audit_decisions
            WHERE tenant_id = ?
              AND created_at >= ?
              AND created_at <= ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            params,
        )


def _extract_event(row: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    payload = _parse_json(row.get("full_decision_json"), {})
    input_snapshot = payload.get("input_snapshot") if isinstance(payload.get("input_snapshot"), dict) else {}
    request = input_snapshot.get("request") if isinstance(input_snapshot.get("request"), dict) else {}
    signal_map = input_snapshot.get("signal_map") if isinstance(input_snapshot.get("signal_map"), dict) else {}

    transition_id = _normalize_text(row.get("link_transition_id")) or _normalize_text(request.get("transition_id"))
    issue_key = _normalize_text(row.get("link_issue_key")) or _normalize_text(request.get("issue_key"))
    actor = _normalize_text(row.get("link_actor")) or _normalize_text(request.get("actor_account_id"))
    source_status = _normalize_text(row.get("link_source_status")) or _normalize_text(request.get("source_status"))
    target_status = _normalize_text(row.get("link_target_status")) or _normalize_text(request.get("target_status"))
    environment = _normalize_text(request.get("environment"))
    project_key = _normalize_text(request.get("project_key"))
    context_overrides = request.get("context_overrides") if isinstance(request.get("context_overrides"), dict) else {}
    workflow_id = _normalize_text(context_overrides.get("workflow_id")) or _normalize_text(request.get("transition_name"))

    if not transition_id:
        return None, "missing_context"

    original_status = _normalize_text(row.get("release_status")).upper()
    original_allow = original_status in {"ALLOWED", "CONDITIONAL"}
    reason_codes = []
    payload_reason = _normalize_text(payload.get("reason_code"))
    if payload_reason:
        reason_codes.append(payload_reason)

    score = _risk_score(signal_map)
    return {
        "decision_id": _normalize_text(row.get("decision_id")),
        "created_at": _normalize_text(row.get("created_at")),
        "occurred_at": _parse_timestamp(row.get("created_at")).isoformat(),
        "issue_key": issue_key,
        "transition_id": transition_id,
        "actor": actor,
        "source_status": source_status,
        "target_status": target_status,
        "environment": environment,
        "project_key": project_key,
        "workflow_id": workflow_id,
        "original_status": original_status,
        "original_allow": original_allow,
        "original_reason_codes": reason_codes,
        "risk_score": score,
        "risk_bucket": _risk_bucket(score),
    }, None


def _event_matches_filters(
    event: Dict[str, Any],
    *,
    transition_id: Optional[str],
    project_key: Optional[str],
    workflow_id: Optional[str],
    environment: Optional[str],
    only_protected: bool,
) -> bool:
    if transition_id and _normalize_text(event.get("transition_id")) != _normalize_text(transition_id):
        return False
    if project_key and _normalize_lower(event.get("project_key")) != _normalize_lower(project_key):
        return False
    if workflow_id and _normalize_lower(event.get("workflow_id")) != _normalize_lower(workflow_id):
        return False
    if environment and _normalize_lower(event.get("environment")) != _normalize_lower(environment):
        return False
    if only_protected and not _is_protected_status(_normalize_text(event.get("target_status"))):
        return False
    return True


def _top_workflows(entries: Dict[Tuple[str, str, str, str, str], Dict[str, int]], top_n: int) -> List[Dict[str, Any]]:
    ordered = sorted(
        entries.items(),
        key=lambda item: (
            int(item[1].get("would_block", 0)),
            abs(int(item[1].get("net_change", 0))),
        ),
        reverse=True,
    )
    result: List[Dict[str, Any]] = []
    for key, stats in ordered[:top_n]:
        project_key, environment, workflow_id, transition_id, target_status = key
        result.append(
            {
                "project_key": project_key,
                "environment": environment,
                "workflow_id": workflow_id,
                "transition_id": transition_id,
                "target_status": target_status,
                "would_block": int(stats.get("would_block", 0)),
                "would_allow": int(stats.get("would_allow", 0)),
                "net_change": int(stats.get("net_change", 0)),
            }
        )
    return result


def _top_risk_clusters(
    clusters: Dict[str, Dict[str, Any]],
    *,
    top_n: int,
) -> List[Dict[str, Any]]:
    ordered = sorted(clusters.items(), key=lambda item: int(item[1].get("count", 0)), reverse=True)
    result: List[Dict[str, Any]] = []
    for cluster_key, payload in ordered[:top_n]:
        reasons = payload.get("reasons") if isinstance(payload.get("reasons"), Counter) else Counter()
        result.append(
            {
                "cluster": cluster_key,
                "count": int(payload.get("count", 0)),
                "risk_bucket": payload.get("risk_bucket"),
                "environment": payload.get("environment"),
                "target_status": payload.get("target_status"),
                "project_key": payload.get("project_key"),
                "top_reasons": [reason for reason, _ in reasons.most_common(3)],
            }
        )
    return result


def simulate_historical_policy_impact(
    *,
    tenant_id: Optional[str],
    actor: Optional[str],
    policy_id: Optional[str],
    policy_version: Optional[int],
    policy_json: Optional[Dict[str, Any]],
    time_window_days: int,
    transition_id: Optional[str] = None,
    project_key: Optional[str] = None,
    workflow_id: Optional[str] = None,
    environment: Optional[str] = None,
    only_protected: bool = False,
    max_events: Optional[int] = None,
    top_n: int = _DEFAULT_TOP_N,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    window_days = int(time_window_days)
    if window_days not in _WINDOW_CHOICES:
        raise ValueError("time_window_days must be one of 30, 60, 90")
    resolved_max_events = int(max_events or _DEFAULT_MAX_EVENTS)
    if resolved_max_events <= 0:
        raise ValueError("max_events must be > 0")
    resolved_max_events = min(resolved_max_events, _MAX_EVENTS_HARD_CAP)
    resolved_top_n = max(1, min(int(top_n), 50))

    candidate = _resolve_candidate_policy(
        tenant_id=effective_tenant,
        policy_id=policy_id,
        policy_version=policy_version,
        policy_json=policy_json,
    )
    candidate_policy = candidate.get("policy_json") if isinstance(candidate.get("policy_json"), dict) else {}

    window_end = _utc_now()
    window_start = window_end - timedelta(days=window_days)
    rows = _fetch_historical_rows(
        tenant_id=effective_tenant,
        window_start=window_start,
        window_end=window_end,
        max_events=resolved_max_events,
    )
    truncated = len(rows) > resolved_max_events
    if truncated:
        rows = rows[:resolved_max_events]

    scanned_events = len(rows)
    skipped_missing_context = 0
    skipped_filtered = 0
    simulated_events = 0

    would_block_count = 0
    would_allow_count = 0
    unchanged_count = 0
    deny_reasons = Counter()
    workflow_impact: Dict[Tuple[str, str, str, str, str], Dict[str, int]] = defaultdict(
        lambda: {"would_block": 0, "would_allow": 0, "net_change": 0}
    )
    risk_clusters: Dict[str, Dict[str, Any]] = {}

    for row in rows:
        event, error = _extract_event(row)
        if not event:
            if error == "missing_context":
                skipped_missing_context += 1
            else:
                skipped_filtered += 1
            continue
        if not _event_matches_filters(
            event,
            transition_id=transition_id,
            project_key=project_key,
            workflow_id=workflow_id,
            environment=environment,
            only_protected=bool(only_protected),
        ):
            skipped_filtered += 1
            continue

        simulated_events += 1
        evaluation = _evaluate_effective_policy(
            effective_policy=candidate_policy,
            transition_id=_normalize_text(event.get("transition_id")),
            project_id=_normalize_text(event.get("project_key")) or None,
            workflow_id=_normalize_text(event.get("workflow_id")) or None,
            environment=_normalize_text(event.get("environment")) or None,
        )
        candidate_allow = bool(evaluation.get("allow"))
        original_allow = bool(event.get("original_allow"))
        candidate_reasons = [str(code) for code in (evaluation.get("reason_codes") or []) if str(code)]

        workflow_key = (
            _normalize_text(event.get("project_key")) or "unknown",
            _normalize_text(event.get("environment")) or "unknown",
            _normalize_text(event.get("workflow_id")) or "unknown",
            _normalize_text(event.get("transition_id")) or "unknown",
            _normalize_text(event.get("target_status")) or "unknown",
        )

        if original_allow and not candidate_allow:
            would_block_count += 1
            deny_reasons.update(candidate_reasons)
            workflow_impact[workflow_key]["would_block"] += 1
            workflow_impact[workflow_key]["net_change"] += 1

            cluster_key = "|".join(
                [
                    _normalize_text(event.get("risk_bucket")) or "unknown",
                    workflow_key[1],
                    workflow_key[4],
                    workflow_key[0],
                ]
            )
            existing = risk_clusters.get(cluster_key)
            if not existing:
                existing = {
                    "count": 0,
                    "risk_bucket": _normalize_text(event.get("risk_bucket")) or "unknown",
                    "environment": workflow_key[1],
                    "target_status": workflow_key[4],
                    "project_key": workflow_key[0],
                    "reasons": Counter(),
                }
            existing["count"] += 1
            existing["reasons"].update(candidate_reasons)
            risk_clusters[cluster_key] = existing
        elif (not original_allow) and candidate_allow:
            would_allow_count += 1
            workflow_impact[workflow_key]["would_allow"] += 1
            workflow_impact[workflow_key]["net_change"] -= 1
        else:
            unchanged_count += 1

    simulation_id = str(uuid.uuid4())
    return {
        "simulation_id": simulation_id,
        "trace_id": simulation_id,
        "enforced": False,
        "tenant_id": effective_tenant,
        "actor": actor,
        "time_window_days": window_days,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "policy_ref": {
            "policy_id": candidate.get("policy_id"),
            "policy_version": candidate.get("policy_version"),
            "policy_hash": candidate.get("policy_hash"),
            "source": candidate.get("source"),
        },
        "scanned_events": scanned_events,
        "simulated_events": simulated_events,
        "skipped_events": skipped_missing_context + skipped_filtered,
        "skipped_missing_context": skipped_missing_context,
        "skipped_filtered": skipped_filtered,
        "truncated": truncated,
        "max_events": resolved_max_events,
        "would_block_count": would_block_count,
        "would_allow_count": would_allow_count,
        "unchanged_count": unchanged_count,
        "override_delta": would_block_count - would_allow_count,
        "delta_breakdown": {
            "allow_to_deny": would_block_count,
            "deny_to_allow": would_allow_count,
            "unchanged": unchanged_count,
        },
        "impacted_workflows": _top_workflows(workflow_impact, resolved_top_n),
        "high_risk_clusters": _top_risk_clusters(risk_clusters, top_n=resolved_top_n),
        "deny_reasons_histogram": [
            {"reason": reason, "count": count}
            for reason, count in deny_reasons.most_common(resolved_top_n)
        ],
        "filters": {
            "transition_id": _normalize_text(transition_id) or None,
            "project_key": _normalize_text(project_key) or None,
            "workflow_id": _normalize_text(workflow_id) or None,
            "environment": _normalize_text(environment) or None,
            "only_protected": bool(only_protected),
        },
    }
