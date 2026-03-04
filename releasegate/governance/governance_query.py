from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


DEFAULT_LIMIT = 100
MAX_LIMIT = 500
DEFAULT_WINDOW_DAYS = 30
MAX_SCAN_ROWS = 50000

_SQL_DECISION_ARCHIVE_PAGE = """
    SELECT
        d.tenant_id,
        d.decision_id,
        d.created_at,
        d.release_status,
        d.full_decision_json,
        d.repo,
        d.pr_number,
        dtl.jira_issue_id,
        dtl.transition_id AS linked_transition_id,
        dtl.actor AS linked_actor,
        CASE WHEN EXISTS (
            SELECT 1
            FROM audit_overrides o
            WHERE o.tenant_id = d.tenant_id AND o.decision_id = d.decision_id
        ) THEN 1 ELSE 0 END AS override_used
    FROM audit_decisions d
    LEFT JOIN decision_transition_links dtl
      ON dtl.tenant_id = d.tenant_id
     AND dtl.decision_id = d.decision_id
    WHERE d.tenant_id = ?
      AND d.created_at >= ?
      AND d.created_at <= ?
    ORDER BY d.created_at DESC, d.decision_id DESC
    LIMIT ?
"""

_SQL_DECISION_ARCHIVE_PAGE_WITH_CURSOR = """
    SELECT
        d.tenant_id,
        d.decision_id,
        d.created_at,
        d.release_status,
        d.full_decision_json,
        d.repo,
        d.pr_number,
        dtl.jira_issue_id,
        dtl.transition_id AS linked_transition_id,
        dtl.actor AS linked_actor,
        CASE WHEN EXISTS (
            SELECT 1
            FROM audit_overrides o
            WHERE o.tenant_id = d.tenant_id AND o.decision_id = d.decision_id
        ) THEN 1 ELSE 0 END AS override_used
    FROM audit_decisions d
    LEFT JOIN decision_transition_links dtl
      ON dtl.tenant_id = d.tenant_id
     AND dtl.decision_id = d.decision_id
    WHERE d.tenant_id = ?
      AND d.created_at >= ?
      AND d.created_at <= ?
      AND (d.created_at < ? OR (d.created_at = ? AND d.decision_id < ?))
    ORDER BY d.created_at DESC, d.decision_id DESC
    LIMIT ?
"""


@dataclass
class DecisionArchiveFilters:
    from_ts: Optional[str] = None
    to_ts: Optional[str] = None
    decision_status: Optional[str] = None
    risk_min: Optional[float] = None
    risk_max: Optional[float] = None
    risk_band: Optional[str] = None
    override_used: Optional[bool] = None
    workflow_id: Optional[str] = None
    transition_id: Optional[str] = None
    actor: Optional[str] = None
    environment: Optional[str] = None
    project_key: Optional[str] = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
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


def _window_bounds(from_ts: Optional[str], to_ts: Optional[str]) -> Tuple[datetime, datetime]:
    now = _utc_now()
    parsed_from = _parse_datetime(from_ts)
    parsed_to = _parse_datetime(to_ts)
    if parsed_from is None and parsed_to is None:
        parsed_to = now
        parsed_from = now - timedelta(days=DEFAULT_WINDOW_DAYS)
    elif parsed_from is None and parsed_to is not None:
        parsed_from = parsed_to - timedelta(days=DEFAULT_WINDOW_DAYS)
    elif parsed_from is not None and parsed_to is None:
        parsed_to = now

    if parsed_from is None or parsed_to is None:
        raise ValueError("invalid time window")
    if parsed_from > parsed_to:
        raise ValueError("from must be before to")
    return parsed_from, parsed_to


def _decode_cursor(cursor: Optional[str]) -> Optional[Tuple[str, str]]:
    raw = str(cursor or "").strip()
    if not raw:
        return None
    padded = raw + "=" * (-len(raw) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
    except (json.JSONDecodeError, TypeError, base64.binascii.Error) as exc:
        raise ValueError("invalid cursor") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid cursor")
    created_at = str(payload.get("created_at") or "").strip()
    decision_id = str(payload.get("decision_id") or "").strip()
    if not created_at or not decision_id:
        raise ValueError("invalid cursor")
    return created_at, decision_id


def _encode_cursor(*, created_at: str, decision_id: str) -> str:
    payload = {"created_at": created_at, "decision_id": decision_id}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _load_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _extract_request(full_decision_json: Any) -> Dict[str, Any]:
    payload = _load_json(full_decision_json)
    input_snapshot = payload.get("input_snapshot") if isinstance(payload.get("input_snapshot"), dict) else {}
    request = input_snapshot.get("request") if isinstance(input_snapshot.get("request"), dict) else {}
    if request:
        return request
    fallback: Dict[str, Any] = {}
    for key in ("issue_key", "transition_id", "project_key", "environment", "actor_id"):
        if key in payload:
            fallback[key] = payload.get(key)
    return fallback


def _extract_risk_meta(full_decision_json: Any) -> Dict[str, Any]:
    payload = _load_json(full_decision_json)
    input_snapshot = payload.get("input_snapshot") if isinstance(payload.get("input_snapshot"), dict) else {}
    risk_meta = input_snapshot.get("risk_meta") if isinstance(input_snapshot.get("risk_meta"), dict) else {}
    if risk_meta:
        return risk_meta
    signal_map = input_snapshot.get("signal_map") if isinstance(input_snapshot.get("signal_map"), dict) else {}
    risk_signal = signal_map.get("risk") if isinstance(signal_map.get("risk"), dict) else {}
    if risk_signal:
        return risk_signal
    return {}


def _normalize_risk_score(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if not isinstance(value, (int, float)):
        return None
    score = float(value)
    if score < 0:
        return None
    if score > 1.0 and score <= 100.0:
        score = score / 100.0
    if score > 1.0:
        score = 1.0
    return round(score, 6)


def _band_from_score(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 0.9:
        return "CRITICAL"
    if score >= 0.7:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    return "LOW"


def _normalize_risk_band(value: Any, score: Optional[float]) -> Optional[str]:
    raw = str(value or "").strip().upper()
    if raw in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return raw
    return _band_from_score(score)


def _normalize_status(status: str) -> str:
    normalized = str(status or "").strip().upper()
    if normalized == "ALLOWED":
        return "ALLOWED"
    if normalized in {"BLOCKED", "ERROR", "DENIED"}:
        return "DENIED"
    return normalized or "UNKNOWN"


def _matches_filters(item: Dict[str, Any], filters: DecisionArchiveFilters) -> bool:
    if filters.decision_status:
        expected_status = _normalize_status(str(filters.decision_status or ""))
        if str(item.get("decision_status") or "") != expected_status:
            return False
    override_used = _normalize_bool(filters.override_used)
    if override_used is not None and bool(item.get("override_used")) is not override_used:
        return False
    if filters.risk_min is not None:
        risk_score = item.get("risk_score")
        if risk_score is None or float(risk_score) < float(filters.risk_min):
            return False
    if filters.risk_max is not None:
        risk_score = item.get("risk_score")
        if risk_score is None or float(risk_score) > float(filters.risk_max):
            return False
    if filters.risk_band:
        if str(item.get("risk_band") or "").upper() != str(filters.risk_band).upper():
            return False
    if filters.workflow_id:
        if str(item.get("workflow_id") or "") != str(filters.workflow_id):
            return False
    if filters.transition_id:
        if str(item.get("transition_id") or "") != str(filters.transition_id):
            return False
    if filters.actor:
        if str(item.get("actor") or "") != str(filters.actor):
            return False
    if filters.environment:
        if str(item.get("environment") or "") != str(filters.environment):
            return False
    if filters.project_key:
        if str(item.get("project_key") or "") != str(filters.project_key):
            return False
    return True


def _normalize_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raw = str(value).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError("value must be a recognizable boolean string (e.g., 'true', 'false', '1', '0')")


def search_decisions(
    *,
    tenant_id: str,
    filters: DecisionArchiveFilters,
    limit: int = DEFAULT_LIMIT,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)

    bounded_limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    window_start, window_end = _window_bounds(filters.from_ts, filters.to_ts)
    cursor_token = _decode_cursor(cursor)
    # Validate early so bad values fail once before scanning rows.
    _normalize_bool(filters.override_used)

    params: List[Any] = [effective_tenant, window_start.isoformat(), window_end.isoformat()]

    scan_cursor = cursor_token
    batch_size = min(max(bounded_limit * 4, 200), 2000)
    scanned = 0
    results: List[Dict[str, Any]] = []
    next_cursor: Optional[str] = None

    while len(results) < bounded_limit and scanned < MAX_SCAN_ROWS:
        if scan_cursor is None:
            rows = storage.fetchall(
                _SQL_DECISION_ARCHIVE_PAGE,
                [*params, batch_size],
            )
        else:
            rows = storage.fetchall(
                _SQL_DECISION_ARCHIVE_PAGE_WITH_CURSOR,
                [*params, scan_cursor[0], scan_cursor[0], scan_cursor[1], batch_size],
            )
        if not rows:
            break

        for row in rows:
            scanned += 1
            payload_request = _extract_request(row.get("full_decision_json"))
            risk_meta = _extract_risk_meta(row.get("full_decision_json"))

            risk_score = _normalize_risk_score(
                risk_meta.get("risk_score")
                if isinstance(risk_meta, dict)
                else None
            )
            if risk_score is None and isinstance(risk_meta, dict):
                risk_score = _normalize_risk_score(risk_meta.get("severity"))
            if risk_score is None:
                signal_map = _load_json(row.get("full_decision_json")).get("input_snapshot", {}).get("signal_map", {})
                if isinstance(signal_map, dict):
                    risk_block = signal_map.get("risk") if isinstance(signal_map.get("risk"), dict) else {}
                    risk_score = _normalize_risk_score(risk_block.get("score"))

            risk_band = _normalize_risk_band(
                (risk_meta or {}).get("risk_level")
                or (risk_meta or {}).get("releasegate_risk")
                or (risk_meta or {}).get("level"),
                risk_score,
            )
            workflow_id = (
                (payload_request.get("context_overrides") or {}).get("workflow_id")
                if isinstance(payload_request.get("context_overrides"), dict)
                else None
            )
            if not workflow_id:
                workflow_id = payload_request.get("workflow_id") or payload_request.get("transition_name")

            item = {
                "tenant_id": str(row.get("tenant_id") or effective_tenant),
                "decision_id": str(row.get("decision_id") or ""),
                "created_at": str(row.get("created_at") or ""),
                "decision_status": _normalize_status(str(row.get("release_status") or "")),
                "risk_score": risk_score,
                "risk_band": risk_band,
                "override_used": bool(int(row.get("override_used") or 0)),
                "jira_issue_id": str(
                    row.get("jira_issue_id")
                    or payload_request.get("issue_key")
                    or ""
                ),
                "workflow_id": str(workflow_id or ""),
                "transition_id": str(
                    row.get("linked_transition_id")
                    or payload_request.get("transition_id")
                    or ""
                ),
                "actor": str(
                    row.get("linked_actor")
                    or payload_request.get("actor_account_id")
                    or payload_request.get("actor_id")
                    or ""
                ),
                "environment": str(payload_request.get("environment") or ""),
                "project_key": str(payload_request.get("project_key") or ""),
            }
            if not _matches_filters(item, filters):
                if scanned >= MAX_SCAN_ROWS:
                    break
                continue

            results.append(item)
            if len(results) >= bounded_limit:
                next_cursor = _encode_cursor(
                    created_at=item["created_at"],
                    decision_id=item["decision_id"],
                )
                break
            if scanned >= MAX_SCAN_ROWS:
                break

        if len(rows) < batch_size:
            break
        last = rows[-1]
        scan_cursor = (str(last.get("created_at") or ""), str(last.get("decision_id") or ""))
        if not scan_cursor[0] or not scan_cursor[1]:
            break

    return {
        "results": results,
        "next_cursor": next_cursor,
        "truncated": bool(next_cursor),
        "scanned_events": scanned,
    }
