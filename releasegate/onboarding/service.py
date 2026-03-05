from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.integrations.jira.client import JiraClient, JiraClientError
from releasegate.integrations.jira.config import load_transition_map
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db

ONBOARDING_MODES = {"simulation", "canary", "strict"}
CONFIGURED_WORKFLOW_ID = "configured-transition-map"
CONFIGURED_WORKFLOW_NAME = "Configured Transition Map"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_json_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    return []


def _normalize_str_list(values: List[str]) -> List[str]:
    normalized: List[str] = []
    seen = set()
    for value in values:
        item = str(value or "").strip()
        if not item:
            continue
        if item in seen:
            continue
        normalized.append(item)
        seen.add(item)
    return normalized


def normalize_onboarding_mode(mode: str) -> str:
    normalized = str(mode or "simulation").strip().lower()
    if normalized not in ONBOARDING_MODES:
        raise ValueError("mode must be one of simulation, canary, strict")
    return normalized


def normalize_canary_pct(*, mode: str, canary_pct: Optional[int]) -> Optional[int]:
    normalized_mode = normalize_onboarding_mode(mode)
    if normalized_mode != "canary":
        return None
    if canary_pct is None:
        return 10
    parsed = int(canary_pct)
    if parsed < 1 or parsed > 100:
        raise ValueError("canary_pct must be between 1 and 100")
    return parsed


def _fallback_transition_map() -> Optional[Any]:
    try:
        return load_transition_map("releasegate/integrations/jira/jira_transition_map.yaml")
    except Exception:
        return None


def _fallback_projects() -> List[Dict[str, Any]]:
    transition_map = _fallback_transition_map()
    if not transition_map:
        return [{"project_key": "*", "name": "All Projects", "project_id": None}]
    project_keys = set(transition_map.jira.project_keys or [])
    for rule in transition_map.transitions:
        for project_key in rule.project_keys:
            cleaned = str(project_key or "").strip()
            if cleaned:
                project_keys.add(cleaned)
    if not project_keys:
        return [{"project_key": "*", "name": "All Projects", "project_id": None}]
    return [
        {"project_key": key, "name": key, "project_id": None}
        for key in sorted(project_keys)
    ]


def _fallback_workflows(project_key: Optional[str]) -> List[Dict[str, Any]]:
    transition_map = _fallback_transition_map()
    if not transition_map:
        return []
    project_filter = str(project_key or "").strip()
    candidate_projects = set(transition_map.jira.project_keys or [])
    for rule in transition_map.transitions:
        for key in rule.project_keys:
            cleaned = str(key or "").strip()
            if cleaned:
                candidate_projects.add(cleaned)
    if not candidate_projects:
        candidate_projects = {"*"}
    if project_filter and project_filter not in candidate_projects and "*" not in candidate_projects:
        return []
    return [
        {
            "workflow_id": CONFIGURED_WORKFLOW_ID,
            "workflow_name": CONFIGURED_WORKFLOW_NAME,
            "project_keys": sorted(candidate_projects),
        }
    ]


def _fallback_workflow_transitions(workflow_id: str, project_key: Optional[str]) -> List[Dict[str, Any]]:
    if str(workflow_id or "").strip() != CONFIGURED_WORKFLOW_ID:
        return []
    transition_map = _fallback_transition_map()
    if not transition_map:
        return []
    project_filter = str(project_key or "").strip()
    rows: List[Dict[str, Any]] = []
    for index, rule in enumerate(transition_map.transitions):
        scoped_projects = set(rule.project_keys or transition_map.jira.project_keys or ["*"])
        if project_filter and project_filter not in scoped_projects and "*" not in scoped_projects:
            continue
        transition_id = str(rule.transition_id or "").strip()
        transition_name = str(rule.transition_name or transition_id or f"transition-{index + 1}").strip()
        if not transition_id:
            transition_id = f"name:{transition_name.lower().replace(' ', '-')}"
        rows.append(
            {
                "transition_id": transition_id,
                "transition_name": transition_name,
                "workflow_id": CONFIGURED_WORKFLOW_ID,
                "workflow_name": CONFIGURED_WORKFLOW_NAME,
                "project_keys": sorted(scoped_projects),
                "mode": str(rule.mode or "permissive"),
            }
        )
    return rows


def _jira_client() -> Optional[JiraClient]:
    try:
        client = JiraClient()
    except Exception:
        return None
    if not client.base_url or not client.email or not client.token:
        return None
    return client


def discover_jira_projects() -> Dict[str, Any]:
    client = _jira_client()
    if client is not None:
        try:
            projects = client.list_projects()
            if projects:
                return {"source": "jira", "items": projects}
        except JiraClientError:
            pass
    return {"source": "configured_map", "items": _fallback_projects()}


def discover_jira_workflows(*, project_key: Optional[str] = None) -> Dict[str, Any]:
    project_filter = str(project_key or "").strip() or None
    client = _jira_client()
    if client is not None:
        try:
            workflows = client.list_workflows(project_key=project_filter)
            if workflows:
                return {"source": "jira", "items": workflows}
        except JiraClientError:
            pass
    return {"source": "configured_map", "items": _fallback_workflows(project_filter)}


def discover_jira_workflow_transitions(
    *,
    workflow_id: str,
    project_key: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_workflow_id = str(workflow_id or "").strip()
    if not normalized_workflow_id:
        raise ValueError("workflow_id is required")
    project_filter = str(project_key or "").strip() or None
    client = _jira_client()
    if client is not None:
        try:
            transitions = client.list_workflow_transitions(
                workflow_id=normalized_workflow_id,
                project_key=project_filter,
            )
            if transitions:
                return {"source": "jira", "items": transitions}
        except JiraClientError:
            pass
    return {
        "source": "configured_map",
        "items": _fallback_workflow_transitions(normalized_workflow_id, project_filter),
    }


def _serialize_onboarding_row(row: Dict[str, Any]) -> Dict[str, Any]:
    mode = normalize_onboarding_mode(str(row.get("mode") or "simulation"))
    canary_pct_raw = row.get("canary_pct")
    canary_pct = int(canary_pct_raw) if canary_pct_raw is not None else None
    if mode != "canary":
        canary_pct = None
    return {
        "tenant_id": str(row.get("tenant_id") or ""),
        "jira_instance_id": str(row.get("jira_instance_id") or "").strip() or None,
        "project_keys": _parse_json_list(row.get("project_keys_json")),
        "workflow_ids": _parse_json_list(row.get("workflow_ids_json")),
        "transition_ids": _parse_json_list(row.get("transition_ids_json")),
        "mode": mode,
        "canary_pct": canary_pct,
        "created_at": str(row.get("created_at") or ""),
        "updated_at": str(row.get("updated_at") or ""),
    }


@dataclass
class ActivationState:
    mode: str
    canary_pct: Optional[int]
    updated_at: Optional[str]


def get_onboarding_status(*, tenant_id: Optional[str]) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT
            tenant_id,
            jira_instance_id,
            project_keys_json,
            workflow_ids_json,
            transition_ids_json,
            mode,
            canary_pct,
            created_at,
            updated_at
        FROM tenant_onboarding_config
        WHERE tenant_id = ?
        LIMIT 1
        """,
        (effective_tenant,),
    )
    if not row:
        return {
            "tenant_id": effective_tenant,
            "onboarding_completed": False,
            "config": {
                "tenant_id": effective_tenant,
                "jira_instance_id": None,
                "project_keys": [],
                "workflow_ids": [],
                "transition_ids": [],
                "mode": "simulation",
                "canary_pct": None,
                "created_at": None,
                "updated_at": None,
            },
        }
    return {
        "tenant_id": effective_tenant,
        "onboarding_completed": True,
        "config": _serialize_onboarding_row(row),
    }


def save_onboarding_config(
    *,
    tenant_id: Optional[str],
    jira_instance_id: Optional[str],
    project_keys: List[str],
    workflow_ids: List[str],
    transition_ids: List[str],
    mode: str,
    canary_pct: Optional[int],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_mode = normalize_onboarding_mode(mode)
    normalized_canary_pct = normalize_canary_pct(mode=normalized_mode, canary_pct=canary_pct)
    normalized_projects = _normalize_str_list(project_keys)
    normalized_workflows = _normalize_str_list(workflow_ids)
    normalized_transitions = _normalize_str_list(transition_ids)
    normalized_jira_instance = str(jira_instance_id or "").strip() or None

    storage = get_storage_backend()
    now_iso = _utc_now_iso()
    existing = storage.fetchone(
        """
        SELECT created_at
        FROM tenant_onboarding_config
        WHERE tenant_id = ?
        LIMIT 1
        """,
        (effective_tenant,),
    )
    created_at = str(existing.get("created_at") or now_iso) if existing else now_iso

    storage.execute(
        """
        INSERT INTO tenant_onboarding_config (
            tenant_id,
            jira_instance_id,
            project_keys_json,
            workflow_ids_json,
            transition_ids_json,
            mode,
            canary_pct,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id) DO UPDATE SET
            jira_instance_id = excluded.jira_instance_id,
            project_keys_json = excluded.project_keys_json,
            workflow_ids_json = excluded.workflow_ids_json,
            transition_ids_json = excluded.transition_ids_json,
            mode = excluded.mode,
            canary_pct = excluded.canary_pct,
            updated_at = excluded.updated_at
        """,
        (
            effective_tenant,
            normalized_jira_instance,
            json.dumps(normalized_projects, separators=(",", ":"), ensure_ascii=False),
            json.dumps(normalized_workflows, separators=(",", ":"), ensure_ascii=False),
            json.dumps(normalized_transitions, separators=(",", ":"), ensure_ascii=False),
            normalized_mode,
            normalized_canary_pct,
            created_at,
            now_iso,
        ),
    )
    return get_onboarding_status(tenant_id=effective_tenant)


def _activation_payload_from_status(status_payload: Dict[str, Any]) -> Dict[str, Any]:
    config = status_payload.get("config") or {}
    mode = normalize_onboarding_mode(str(config.get("mode") or "simulation"))
    canary_pct = config.get("canary_pct")
    if mode == "canary":
        canary_pct = normalize_canary_pct(mode=mode, canary_pct=canary_pct)
    else:
        canary_pct = None
    return {
        "tenant_id": str(status_payload.get("tenant_id") or ""),
        "mode": mode,
        "canary_pct": canary_pct,
        "applied": bool(status_payload.get("onboarding_completed")),
        "updated_at": config.get("updated_at"),
    }


def _activation_state_from_status(status_payload: Dict[str, Any]) -> ActivationState:
    config = status_payload.get("config") or {}
    mode = normalize_onboarding_mode(str(config.get("mode") or "simulation"))
    canary_pct = normalize_canary_pct(mode=mode, canary_pct=config.get("canary_pct"))
    return ActivationState(
        mode=mode,
        canary_pct=canary_pct,
        updated_at=config.get("updated_at"),
    )


def _serialize_activation_history_row(row: Dict[str, Any]) -> Dict[str, Any]:
    mode = normalize_onboarding_mode(str(row.get("mode") or "simulation"))
    canary_pct = normalize_canary_pct(mode=mode, canary_pct=row.get("canary_pct"))
    return {
        "mode": mode,
        "canary_pct": canary_pct,
        "updated_at": row.get("saved_at"),
    }


def _record_activation_history(
    *,
    tenant_id: str,
    state: ActivationState,
) -> None:
    if state.updated_at is None:
        return
    storage = get_storage_backend()
    saved_at = _utc_now_iso()
    storage.execute(
        """
        INSERT INTO tenant_onboarding_activation_history (
            tenant_id,
            mode,
            canary_pct,
            previous_updated_at,
            saved_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            state.mode,
            state.canary_pct,
            state.updated_at,
            saved_at,
        ),
    )
    # Keep only the most recent 10 entries per tenant.
    storage.execute(
        """
        DELETE FROM tenant_onboarding_activation_history
        WHERE tenant_id = ?
          AND history_id NOT IN (
              SELECT history_id
              FROM tenant_onboarding_activation_history
              WHERE tenant_id = ?
              ORDER BY history_id DESC
              LIMIT 10
          )
        """,
        (tenant_id, tenant_id),
    )


def _pop_previous_activation(
    *,
    tenant_id: str,
) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT history_id, mode, canary_pct, saved_at
        FROM tenant_onboarding_activation_history
        WHERE tenant_id = ?
        ORDER BY history_id DESC
        LIMIT 1
        """,
        (tenant_id,),
    )
    if not row:
        return None
    history_id = int(row.get("history_id"))
    storage.execute(
        """
        DELETE FROM tenant_onboarding_activation_history
        WHERE tenant_id = ? AND history_id = ?
        """,
        (tenant_id, history_id),
    )
    return _serialize_activation_history_row(row)


def get_onboarding_activation(*, tenant_id: Optional[str]) -> Dict[str, Any]:
    status_payload = get_onboarding_status(tenant_id=tenant_id)
    return _activation_payload_from_status(status_payload)


def save_onboarding_activation(
    *,
    tenant_id: Optional[str],
    mode: str,
    canary_pct: Optional[int],
) -> Dict[str, Any]:
    normalized_mode = normalize_onboarding_mode(mode)
    if normalized_mode == "canary" and canary_pct is None:
        raise ValueError("canary_pct is required when mode is canary")
    status_payload = get_onboarding_status(tenant_id=tenant_id)
    config = status_payload.get("config") or {}
    previous_state = _activation_state_from_status(status_payload)
    normalized_canary_pct = normalize_canary_pct(mode=normalized_mode, canary_pct=canary_pct)
    if previous_state.mode != normalized_mode or previous_state.canary_pct != normalized_canary_pct:
        _record_activation_history(
            tenant_id=str(status_payload.get("tenant_id") or ""),
            state=previous_state,
        )
    updated_status = save_onboarding_config(
        tenant_id=tenant_id,
        jira_instance_id=config.get("jira_instance_id"),
        project_keys=list(config.get("project_keys") or []),
        workflow_ids=list(config.get("workflow_ids") or []),
        transition_ids=list(config.get("transition_ids") or []),
        mode=normalized_mode,
        canary_pct=normalized_canary_pct,
    )
    return _activation_payload_from_status(updated_status)


def rollback_onboarding_activation(
    *,
    tenant_id: Optional[str],
) -> Dict[str, Any]:
    status_payload = get_onboarding_status(tenant_id=tenant_id)
    effective_tenant = str(status_payload.get("tenant_id") or "")
    previous = _pop_previous_activation(tenant_id=effective_tenant)
    if not previous:
        raise ValueError("No previous activation state")

    config = status_payload.get("config") or {}
    updated_status = save_onboarding_config(
        tenant_id=effective_tenant,
        jira_instance_id=config.get("jira_instance_id"),
        project_keys=list(config.get("project_keys") or []),
        workflow_ids=list(config.get("workflow_ids") or []),
        transition_ids=list(config.get("transition_ids") or []),
        mode=str(previous.get("mode") or "simulation"),
        canary_pct=previous.get("canary_pct"),
    )
    activation_payload = _activation_payload_from_status(updated_status)
    return {
        "status": "rolled_back",
        "activation": activation_payload,
    }
