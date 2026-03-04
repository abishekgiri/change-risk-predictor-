from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from releasegate.audit.reader import AuditReader
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


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


def _decision_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    return _parse_json(row.get("full_decision_json"), {})


def _decision_issue_key(row: Dict[str, Any]) -> str:
    payload = _decision_payload(row)
    input_snapshot = payload.get("input_snapshot") if isinstance(payload.get("input_snapshot"), dict) else {}
    request = input_snapshot.get("request") if isinstance(input_snapshot.get("request"), dict) else {}
    return str(request.get("issue_key") or payload.get("issue_key") or "").strip()


def _decision_anchor_date(row: Dict[str, Any]) -> Optional[str]:
    created_at_raw = row.get("created_at")
    if isinstance(created_at_raw, datetime):
        return created_at_raw.astimezone(timezone.utc).date().isoformat()
    if isinstance(created_at_raw, str):
        raw = created_at_raw.strip()
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
        return dt.astimezone(timezone.utc).date().isoformat()
    return None


def _dedupe_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for node in nodes:
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            continue
        seen[node_id] = node
    return [seen[key] for key in sorted(seen.keys())]


def _dedupe_edges(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for edge in edges:
        edge_key = (
            str(edge.get("from") or ""),
            str(edge.get("to") or ""),
            str(edge.get("type") or ""),
        )
        if not edge_key[0] or not edge_key[1] or not edge_key[2]:
            continue
        seen[edge_key] = edge
    return [seen[key] for key in sorted(seen.keys())]


def build_decision_graph(
    *,
    tenant_id: str,
    decision_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_row = AuditReader.get_decision(decision_id, tenant_id=effective_tenant)
    if not decision_row:
        return None

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    decision_node_id = f"decision:{decision_id}"
    nodes.append(
        {
            "id": decision_node_id,
            "type": "decision",
            "attrs": {
                "decision_id": decision_id,
                "status": decision_row.get("release_status"),
                "repo": decision_row.get("repo"),
                "pr_number": decision_row.get("pr_number"),
                "created_at": decision_row.get("created_at"),
            },
        }
    )

    payload = _decision_payload(decision_row)
    bindings = payload.get("policy_bindings") if isinstance(payload.get("policy_bindings"), list) else []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        policy_id = str(binding.get("policy_id") or "").strip() or "unknown"
        policy_version = str(binding.get("policy_version") or "").strip() or "unknown"
        policy_hash = str(binding.get("policy_hash") or "").strip()
        node_id = f"policy:{policy_id}:{policy_version}:{policy_hash[:12] or 'none'}"
        nodes.append(
            {
                "id": node_id,
                "type": "policy_snapshot",
                "attrs": {
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "policy_hash": policy_hash,
                },
            }
        )
        edges.append({"from": decision_node_id, "to": node_id, "type": "bound_to"})

    approval_rows = storage.fetchall(
        """
        SELECT approval_id, approval_group, approver_actor, approver_role, created_at, revoked_at
        FROM decision_approvals
        WHERE tenant_id = ? AND decision_id = ?
        ORDER BY created_at ASC
        """,
        (effective_tenant, decision_id),
    )
    for row in approval_rows:
        node_id = f"approval:{row.get('approval_id')}"
        nodes.append(
            {
                "id": node_id,
                "type": "approval",
                "attrs": {
                    "approval_id": row.get("approval_id"),
                    "group": row.get("approval_group"),
                    "actor": row.get("approver_actor"),
                    "role": row.get("approver_role"),
                    "created_at": row.get("created_at"),
                    "revoked_at": row.get("revoked_at"),
                },
            }
        )
        edges.append({"from": decision_node_id, "to": node_id, "type": "approved_by"})

    override_rows = storage.fetchall(
        """
        SELECT override_id, actor, reason, created_at, expires_at
        FROM audit_overrides
        WHERE tenant_id = ? AND decision_id = ?
        ORDER BY created_at ASC
        """,
        (effective_tenant, decision_id),
    )
    for row in override_rows:
        node_id = f"override:{row.get('override_id')}"
        nodes.append(
            {
                "id": node_id,
                "type": "override",
                "attrs": {
                    "override_id": row.get("override_id"),
                    "actor": row.get("actor"),
                    "reason": row.get("reason"),
                    "created_at": row.get("created_at"),
                    "expires_at": row.get("expires_at"),
                },
            }
        )
        edges.append({"from": decision_node_id, "to": node_id, "type": "overridden_by"})

    issue_key = ""
    link = storage.fetchone(
        """
        SELECT jira_issue_id
        FROM decision_transition_links
        WHERE tenant_id = ? AND decision_id = ?
        LIMIT 1
        """,
        (effective_tenant, decision_id),
    )
    if link:
        issue_key = str(link.get("jira_issue_id") or "").strip()
    if not issue_key:
        issue_key = _decision_issue_key(decision_row)

    if issue_key:
        signal_rows = storage.fetchall(
            """
            SELECT signal_id, signal_type, signal_source, computed_at, expires_at
            FROM signal_attestations
            WHERE tenant_id = ?
              AND subject_type = 'jira_issue'
              AND subject_id = ?
            ORDER BY computed_at DESC
            LIMIT 25
            """,
            (effective_tenant, issue_key),
        )
        for row in signal_rows:
            node_id = f"signal:{row.get('signal_id')}"
            nodes.append(
                {
                    "id": node_id,
                    "type": "signal_attestation",
                    "attrs": {
                        "signal_id": row.get("signal_id"),
                        "signal_type": row.get("signal_type"),
                        "signal_source": row.get("signal_source"),
                        "computed_at": row.get("computed_at"),
                        "expires_at": row.get("expires_at"),
                        "subject_id": issue_key,
                    },
                }
            )
            edges.append({"from": decision_node_id, "to": node_id, "type": "evaluated_with"})

    deploy_rows = storage.fetchall(
        """
        SELECT deployment_event_id, environment, service, deployed_at, contract_verdict, override_state_at_deploy
        FROM deployment_decision_links
        WHERE tenant_id = ? AND decision_id = ?
        ORDER BY deployed_at ASC
        """,
        (effective_tenant, decision_id),
    )
    for row in deploy_rows:
        node_id = f"deployment:{row.get('deployment_event_id')}"
        nodes.append(
            {
                "id": node_id,
                "type": "deployment",
                "attrs": {
                    "deployment_event_id": row.get("deployment_event_id"),
                    "environment": row.get("environment"),
                    "service": row.get("service"),
                    "deployed_at": row.get("deployed_at"),
                    "contract_verdict": row.get("contract_verdict"),
                    "override_state_at_deploy": row.get("override_state_at_deploy"),
                },
            }
        )
        edges.append({"from": node_id, "to": decision_node_id, "type": "authorized_by"})

    date_utc = _decision_anchor_date(decision_row)
    if date_utc:
        checkpoint_row = storage.fetchone(
            """
            SELECT checkpoint_id, date_utc, ledger_root, checkpoint_hash, anchor_provider, anchor_ref, created_at
            FROM audit_independent_daily_checkpoints
            WHERE tenant_id = ? AND date_utc = ?
            LIMIT 1
            """,
            (effective_tenant, date_utc),
        )
        if checkpoint_row:
            checkpoint_id = str(checkpoint_row.get("checkpoint_id") or date_utc)
            node_id = f"anchor:{checkpoint_id}"
            nodes.append(
                {
                    "id": node_id,
                    "type": "independent_checkpoint",
                    "attrs": {
                        "checkpoint_id": checkpoint_row.get("checkpoint_id"),
                        "date_utc": checkpoint_row.get("date_utc"),
                        "ledger_root": checkpoint_row.get("ledger_root"),
                        "checkpoint_hash": checkpoint_row.get("checkpoint_hash"),
                        "anchor_provider": checkpoint_row.get("anchor_provider"),
                        "anchor_ref": checkpoint_row.get("anchor_ref"),
                        "created_at": checkpoint_row.get("created_at"),
                    },
                }
            )
            edges.append({"from": decision_node_id, "to": node_id, "type": "anchored_in"})

    return {
        "tenant_id": effective_tenant,
        "decision_id": decision_id,
        "nodes": _dedupe_nodes(nodes),
        "edges": _dedupe_edges(edges),
    }
