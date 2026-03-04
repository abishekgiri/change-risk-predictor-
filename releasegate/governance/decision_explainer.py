from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.audit.reader import AuditReader
from releasegate.evidence.graph import explain_decision
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


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


def _request_payload(full_decision: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = full_decision.get("input_snapshot")
    if isinstance(snapshot, dict):
        request = snapshot.get("request")
        if isinstance(request, dict):
            return request
    return {}


def _signal_payload(full_decision: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = full_decision.get("input_snapshot")
    if isinstance(snapshot, dict):
        signals = snapshot.get("signal_map")
        if isinstance(signals, dict):
            return signals
    return {}


def _risk_payload(full_decision: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = full_decision.get("input_snapshot")
    if isinstance(snapshot, dict):
        risk_meta = snapshot.get("risk_meta")
        if isinstance(risk_meta, dict):
            return risk_meta
        signal_map = snapshot.get("signal_map")
        if isinstance(signal_map, dict):
            risk_signal = signal_map.get("risk")
            if isinstance(risk_signal, dict):
                return risk_signal
    return {}


def _to_iso_datetime(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None
    candidate = raw
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _normalized_outcome(status: str) -> str:
    if str(status or "").upper() in {"BLOCKED", "DENIED", "ERROR"}:
        return "BLOCK"
    return "ALLOW"


def _human_block_reason(reason_code: str) -> Optional[str]:
    code = str(reason_code or "").strip().upper()
    if not code:
        return None
    messages = {
        "RISK_TOO_HIGH": "Blocked because risk score exceeded the configured threshold.",
        "OVERRIDE_EXPIRED": "Blocked because the override expired.",
        "OVERRIDE_REQUIRED": "Blocked because an approved override was required.",
        "TENANT_LOCKED": "Blocked because tenant security state is locked.",
        "MISSING_SIGNAL": "Blocked because a required signal attestation is missing.",
        "STALE_SIGNAL": "Blocked because a required signal attestation is stale.",
    }
    return messages.get(code) or f"Blocked due to policy rule: {code.replace('_', ' ').lower()}."


def _normalize_signals(signals: Dict[str, Any]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for name in sorted(signals.keys()):
        raw = signals.get(name)
        source: Optional[str] = None
        confidence: Optional[float] = None
        captured_at: Optional[str] = None
        value: Any = raw
        if isinstance(raw, dict):
            source_raw = raw.get("source") or raw.get("signal_source")
            if source_raw is not None and str(source_raw).strip():
                source = str(source_raw).strip()
            confidence_raw = raw.get("confidence")
            if isinstance(confidence_raw, (int, float)):
                confidence = float(confidence_raw)
            captured_at = _to_iso_datetime(
                raw.get("captured_at") or raw.get("computed_at") or raw.get("timestamp")
            )
            if "value" in raw:
                value = raw.get("value")
            elif "score" in raw:
                value = raw.get("score")
            elif "level" in raw:
                value = raw.get("level")
        normalized.append(
            {
                "name": str(name),
                "value": value,
                "source": source,
                "confidence": confidence,
                "captured_at": captured_at,
            }
        )
    return normalized


def _as_float(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        raw = str(value or "").strip()
        if not raw:
            return None
        return float(raw)
    except ValueError:
        return None


def _normalize_risk(risk: Dict[str, Any], signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    score = _as_float(risk.get("risk_score"))
    if score is None:
        score = _as_float(risk.get("score"))
    if score is None:
        for entry in signals:
            if str(entry.get("name") or "").lower() == "risk":
                score = _as_float(entry.get("value"))
                if score is not None:
                    break
    components: List[Dict[str, Any]] = []
    raw_components = risk.get("components")
    if isinstance(raw_components, list):
        for item in raw_components:
            if not isinstance(item, dict):
                continue
            components.append(
                {
                    "name": str(item.get("name") or "component"),
                    "value": item.get("value"),
                    "weight": _as_float(item.get("weight")),
                    "notes": str(item.get("notes") or "").strip() or None,
                }
            )
    if not components and score is not None:
        components.append(
            {
                "name": "risk_score",
                "value": score,
                "weight": 1.0,
                "notes": str(risk.get("risk_level") or "").strip() or None,
            }
        )
    return {
        "score": float(score or 0.0),
        "components": components,
    }


def _normalize_evaluation_tree(evidence_graph: Any) -> Dict[str, Any]:
    if not isinstance(evidence_graph, dict):
        return {"nodes": [], "edges": []}
    nodes = evidence_graph.get("nodes") if isinstance(evidence_graph.get("nodes"), list) else []
    edges = evidence_graph.get("edges") if isinstance(evidence_graph.get("edges"), list) else []
    normalized_nodes = sorted(
        [node for node in nodes if isinstance(node, dict)],
        key=lambda item: (
            str(item.get("type") or ""),
            str(item.get("ref") or ""),
            str(item.get("node_id") or ""),
        ),
    )
    normalized_edges = sorted(
        [edge for edge in edges if isinstance(edge, dict)],
        key=lambda item: (
            str(item.get("type") or ""),
            str(item.get("from_node_id") or ""),
            str(item.get("to_node_id") or ""),
            str(item.get("edge_id") or ""),
        ),
    )
    return {
        "nodes": normalized_nodes,
        "edges": normalized_edges,
    }


def _build_evidence_links(
    *,
    decision_id: str,
    snapshot_id: Optional[str],
    policy_id: Optional[str],
    evaluation_tree: Dict[str, Any],
) -> List[Dict[str, Any]]:
    links: List[Dict[str, Any]] = [
        {
            "type": "evidence_graph",
            "id": str(decision_id),
            "label": "Decision evidence graph",
            "path": f"/governance/decisions/{decision_id}/graph",
        }
    ]
    if snapshot_id:
        links.append(
            {
                "type": "policy_snapshot",
                "id": str(snapshot_id),
                "label": str(policy_id or "Policy snapshot"),
                "path": None,
            }
        )
    nodes = evaluation_tree.get("nodes") if isinstance(evaluation_tree.get("nodes"), list) else []
    for node in nodes[:5]:
        node_id = str(node.get("node_id") or "").strip()
        if not node_id:
            continue
        links.append(
            {
                "type": "evidence_node",
                "id": node_id,
                "label": str(node.get("type") or "evidence"),
                "path": None,
            }
        )
    return links


def build_decision_explainer(
    *,
    tenant_id: str,
    decision_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_row = AuditReader.get_decision(decision_id, tenant_id=effective_tenant)
    if not decision_row:
        return None

    full_decision = _parse_json(decision_row.get("full_decision_json"))
    request = _request_payload(full_decision)
    signals = _signal_payload(full_decision)
    risk = _risk_payload(full_decision)
    reason_code = str(full_decision.get("reason_code") or "")
    decision_status = str(decision_row.get("release_status") or "")

    evidence = explain_decision(tenant_id=effective_tenant, decision_id=decision_id) or {}
    binding = AuditReader.get_decision_with_policy_snapshot(decision_id, tenant_id=effective_tenant) or {}
    binding_verify = AuditReader.verify_decision_policy_snapshot(decision_id, tenant_id=effective_tenant) or {}

    snapshot_wrapper = binding.get("snapshot") if isinstance(binding, dict) else {}
    snapshot = snapshot_wrapper.get("snapshot") if isinstance(snapshot_wrapper, dict) else {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    policy_bindings = full_decision.get("policy_bindings") if isinstance(full_decision.get("policy_bindings"), list) else []
    primary_binding = policy_bindings[0] if policy_bindings and isinstance(policy_bindings[0], dict) else {}

    context_overrides = request.get("context_overrides") if isinstance(request.get("context_overrides"), dict) else {}
    workflow_id = str(
        context_overrides.get("workflow_id")
        or request.get("workflow_id")
        or request.get("transition_name")
        or ""
    )

    outcome = _normalized_outcome(decision_status)
    blocked_reason = _human_block_reason(reason_code) if outcome == "BLOCK" else None
    normalized_signals = _normalize_signals(signals)
    normalized_risk = _normalize_risk(risk, normalized_signals)
    evaluation_tree = _normalize_evaluation_tree(evidence.get("graph"))
    snapshot_hash = str(snapshot.get("policy_hash") or "") or None
    policy_hash = (
        str(primary_binding.get("policy_hash") or "")
        or str(binding.get("policy_hash") or "")
        or str(decision_row.get("policy_hash") or "")
        or None
    )
    decision_hash = str(decision_row.get("decision_hash") or "") or None
    replay_token = (
        str(decision_row.get("replay_hash") or "").strip()
        or str(decision_hash or "").strip()
        or str(decision_id)
    )
    evidence_links = _build_evidence_links(
        decision_id=decision_id,
        snapshot_id=str(binding.get("snapshot_id") or "").strip() or None,
        policy_id=str(primary_binding.get("policy_id") or binding.get("policy_id") or "").strip() or None,
        evaluation_tree=evaluation_tree,
    )
    replay_path = f"/decisions/{decision_id}/replay"

    payload = {
        "tenant_id": effective_tenant,
        "decision_id": decision_id,
        "decision": {
            "decision_id": decision_id,
            "created_at": _to_iso_datetime(decision_row.get("created_at")) or decision_row.get("created_at"),
            "outcome": outcome,
            "blocked_because": blocked_reason,
            "reason_code": reason_code or None,
            "status": decision_status,
            "repo": decision_row.get("repo"),
            "pr_number": decision_row.get("pr_number"),
            "jira_issue_id": request.get("issue_key"),
            "workflow_id": workflow_id or None,
            "transition_id": request.get("transition_id"),
            "actor": request.get("actor_account_id") or request.get("actor_id"),
            "environment": request.get("environment"),
            "project_key": request.get("project_key"),
        },
        "snapshot_binding": {
            "policy_hash": policy_hash,
            "snapshot_hash": snapshot_hash,
            "decision_hash": decision_hash,
            "binding_verified": bool(binding_verify.get("verified")),
        },
        "evaluation_tree": evaluation_tree,
        "signals": normalized_signals,
        "risk": normalized_risk,
        "evidence_links": evidence_links,
        "replay": {
            "path": replay_path,
            "token": replay_token,
            "expires_at": None,
        },
    }

    # Backward-compatible aliases for existing callers.
    payload["summary"] = evidence.get("summary")
    payload["why_blocked"] = blocked_reason
    payload["policy_binding"] = {
        "policy_id": primary_binding.get("policy_id") or binding.get("policy_id"),
        "policy_version": primary_binding.get("policy_version") or binding.get("snapshot_id"),
        "policy_hash": policy_hash,
        "snapshot_hash": snapshot_hash,
        "binding_verified": bool(binding_verify.get("verified")),
        "binding": binding_verify,
    }
    payload["risk_components"] = normalized_risk
    payload["evidence"] = evidence.get("evidence")
    return payload
