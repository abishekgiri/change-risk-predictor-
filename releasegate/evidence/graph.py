from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from releasegate.audit.reader import AuditReader
from releasegate.replay.events import list_replay_events
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


NODE_DECISION = "DECISION"
NODE_POLICY_SNAPSHOT = "POLICY_SNAPSHOT"
NODE_SIGNAL_BUNDLE = "SIGNAL_BUNDLE"
NODE_PULL_REQUEST = "PULL_REQUEST"
NODE_JIRA_ISSUE = "JIRA_ISSUE"
NODE_ATTESTATION = "ATTESTATION"
NODE_REPLAY = "REPLAY"
NODE_DEPLOYMENT = "DEPLOYMENT"
NODE_INCIDENT = "INCIDENT"
NODE_ARTIFACT = "ARTIFACT"
NODE_OVERRIDE = "OVERRIDE"
NODE_CHECKPOINT = "CHECKPOINT"
NODE_EXTERNAL_ANCHOR = "EXTERNAL_ANCHOR"

EDGE_USED_POLICY = "USED_POLICY"
EDGE_USED_SIGNAL = "USED_SIGNAL"
EDGE_RELATED_TO = "RELATED_TO"
EDGE_PRODUCED_ARTIFACT = "PRODUCED_ARTIFACT"
EDGE_REPLAYED = "REPLAYED"
EDGE_AUTHORIZED_BY = "AUTHORIZED_BY"
EDGE_DERIVED_FROM = "DERIVED_FROM"
EDGE_OVERRIDDEN_BY = "OVERRIDDEN_BY"
EDGE_RESOLVED_BY = "RESOLVED_BY"
EDGE_ANCHORED_BY = "ANCHORED_BY"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_load(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return default
    if isinstance(value, (dict, list)):
        return value
    return default


def _placeholder_list(count: int) -> str:
    return ",".join(["?"] * max(1, count))


def _edge_sort_key(edge: Dict[str, Any]) -> tuple:
    return (
        str(edge.get("type") or ""),
        str(edge.get("from_node_id") or ""),
        str(edge.get("to_node_id") or ""),
        str(edge.get("created_at") or ""),
    )


def _node_hash_material(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": str(node.get("type") or ""),
        "ref": str(node.get("ref") or ""),
        "hash": str(node.get("hash") or ""),
        "payload": node.get("payload") if isinstance(node.get("payload"), dict) else {},
    }


def _edge_hash_material(edge: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": str(edge.get("type") or ""),
        "from": str(edge.get("from_node_id") or ""),
        "to": str(edge.get("to_node_id") or ""),
        "metadata": edge.get("metadata") if isinstance(edge.get("metadata"), dict) else {},
    }


def _normalise_node(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tenant_id": row.get("tenant_id"),
        "node_id": row.get("node_id"),
        "type": row.get("type"),
        "ref": row.get("ref"),
        "hash": row.get("hash"),
        "payload": _json_load(row.get("payload_json"), {}),
        "created_at": row.get("created_at"),
    }


def _normalise_edge(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tenant_id": row.get("tenant_id"),
        "edge_id": row.get("edge_id"),
        "from_node_id": row.get("from_node_id"),
        "to_node_id": row.get("to_node_id"),
        "type": row.get("type"),
        "metadata": _json_load(row.get("metadata_json"), {}),
        "created_at": row.get("created_at"),
    }


def _get_node_by_type_ref(
    *,
    tenant_id: str,
    node_type: str,
    ref: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, node_id, type, ref, hash, payload_json, created_at
        FROM evidence_nodes
        WHERE tenant_id = ? AND type = ? AND ref = ?
        LIMIT 1
        """,
        (tenant_id, str(node_type), str(ref)),
    )
    if not row:
        return None
    return _normalise_node(row)


def _get_node_by_id(*, tenant_id: str, node_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, node_id, type, ref, hash, payload_json, created_at
        FROM evidence_nodes
        WHERE tenant_id = ? AND node_id = ?
        LIMIT 1
        """,
        (tenant_id, str(node_id)),
    )
    if not row:
        return None
    return _normalise_node(row)


def upsert_node(
    *,
    tenant_id: Optional[str],
    node_type: str,
    ref: str,
    node_hash: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    existing = _get_node_by_type_ref(
        tenant_id=effective_tenant,
        node_type=str(node_type),
        ref=str(ref),
    )
    if existing:
        return existing

    node_id = str(uuid.uuid4())
    created_at = _utc_now()
    storage.execute(
        """
        INSERT INTO evidence_nodes (
            tenant_id, node_id, type, ref, hash, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            node_id,
            str(node_type),
            str(ref),
            str(node_hash or "") or None,
            canonical_json(payload or {}),
            created_at,
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "node_id": node_id,
        "type": str(node_type),
        "ref": str(ref),
        "hash": str(node_hash or "") or None,
        "payload": payload or {},
        "created_at": created_at,
    }


def append_edge(
    *,
    tenant_id: Optional[str],
    from_node_id: str,
    to_node_id: str,
    edge_type: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)

    existing = storage.fetchone(
        """
        SELECT tenant_id, edge_id, from_node_id, to_node_id, type, metadata_json, created_at
        FROM evidence_edges
        WHERE tenant_id = ? AND from_node_id = ? AND to_node_id = ? AND type = ?
        LIMIT 1
        """,
        (effective_tenant, str(from_node_id), str(to_node_id), str(edge_type)),
    )
    if existing:
        return _normalise_edge(existing)

    edge_id = str(uuid.uuid4())
    created_at = _utc_now()
    storage.execute(
        """
        INSERT INTO evidence_edges (
            tenant_id, edge_id, from_node_id, to_node_id, type, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            edge_id,
            str(from_node_id),
            str(to_node_id),
            str(edge_type),
            canonical_json(metadata or {}),
            created_at,
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "edge_id": edge_id,
        "from_node_id": str(from_node_id),
        "to_node_id": str(to_node_id),
        "type": str(edge_type),
        "metadata": metadata or {},
        "created_at": created_at,
    }


def record_decision_evidence(
    *,
    tenant_id: Optional[str],
    decision_id: str,
    status: str,
    reason_code: Optional[str],
    decision_hash: Optional[str],
    repo: Optional[str],
    pr_number: Optional[int],
    issue_key: Optional[str],
    input_hash: Optional[str],
    policy_snapshot_id: Optional[str],
    policy_hash: Optional[str],
    attestation_id: Optional[str],
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_DECISION,
        ref=str(decision_id),
        node_hash=decision_hash,
        payload={
            "status": str(status),
            "reason_code": str(reason_code or ""),
            "repo": repo,
            "pr_number": pr_number,
            "context": context or {},
        },
    )

    linked_nodes: Dict[str, Dict[str, Any]] = {"decision": decision_node}

    if policy_snapshot_id or policy_hash:
        policy_ref = str(policy_snapshot_id or policy_hash or "")
        policy_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_POLICY_SNAPSHOT,
            ref=policy_ref,
            node_hash=policy_hash,
            payload={"snapshot_id": policy_snapshot_id, "policy_hash": policy_hash},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=decision_node["node_id"],
            to_node_id=policy_node["node_id"],
            edge_type=EDGE_USED_POLICY,
        )
        linked_nodes["policy_snapshot"] = policy_node

    if input_hash:
        signal_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_SIGNAL_BUNDLE,
            ref=f"signal:{input_hash}",
            node_hash=input_hash,
            payload={"signal_bundle_hash": input_hash},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=decision_node["node_id"],
            to_node_id=signal_node["node_id"],
            edge_type=EDGE_USED_SIGNAL,
        )
        linked_nodes["signals"] = signal_node

    if repo and pr_number:
        pr_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_PULL_REQUEST,
            ref=f"{repo}#{pr_number}",
            payload={"repo": repo, "pr_number": pr_number},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=decision_node["node_id"],
            to_node_id=pr_node["node_id"],
            edge_type=EDGE_RELATED_TO,
        )
        linked_nodes["pull_request"] = pr_node

    if issue_key:
        issue_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_JIRA_ISSUE,
            ref=str(issue_key),
            payload={"issue_key": issue_key},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=decision_node["node_id"],
            to_node_id=issue_node["node_id"],
            edge_type=EDGE_RELATED_TO,
        )
        linked_nodes["jira_issue"] = issue_node

    if attestation_id:
        attestation_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_ATTESTATION,
            ref=str(attestation_id),
            payload={"attestation_id": attestation_id},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=decision_node["node_id"],
            to_node_id=attestation_node["node_id"],
            edge_type=EDGE_PRODUCED_ARTIFACT,
        )
        linked_nodes["attestation"] = attestation_node

    override_used = bool((context or {}).get("override_used"))
    if override_used:
        override_ref = str((context or {}).get("override_event_id") or f"override:{decision_id}")
        override_hash = str((context or {}).get("override_hash") or "") or None
        override_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_OVERRIDE,
            ref=override_ref,
            node_hash=override_hash,
            payload={
                "reason": (context or {}).get("override_reason"),
                "expires_at": (context or {}).get("override_expires_at"),
            },
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=decision_node["node_id"],
            to_node_id=override_node["node_id"],
            edge_type=EDGE_OVERRIDDEN_BY,
        )
        linked_nodes["override"] = override_node

    return linked_nodes


def record_replay_evidence(
    *,
    tenant_id: Optional[str],
    decision_id: str,
    replay_id: str,
    match: bool,
    diff: Sequence[Dict[str, Any]],
    replay_hash: Optional[str],
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_DECISION,
        ref=str(decision_id),
        payload={"decision_id": decision_id},
    )
    replay_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_REPLAY,
        ref=str(replay_id),
        node_hash=replay_hash,
        payload={
            "decision_id": decision_id,
            "match": bool(match),
            "diff_count": len(list(diff or [])),
        },
    )
    append_edge(
        tenant_id=effective_tenant,
        from_node_id=replay_node["node_id"],
        to_node_id=decision_node["node_id"],
        edge_type=EDGE_REPLAYED,
        metadata={"match": bool(match)},
    )
    return {"decision": decision_node, "replay": replay_node}


def record_deployment_evidence(
    *,
    tenant_id: Optional[str],
    deploy_ref: str,
    decision_id: str,
    issue_key: Optional[str],
    correlation_id: str,
    commit_sha: Optional[str],
    artifact_digest: Optional[str],
    env: str,
    authorized: bool,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_DECISION,
        ref=str(decision_id),
        payload={"decision_id": decision_id},
    )
    deployment_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_DEPLOYMENT,
        ref=str(deploy_ref),
        payload={
            "correlation_id": correlation_id,
            "env": env,
            "commit_sha": commit_sha,
            "artifact_digest": artifact_digest,
            "authorized": bool(authorized),
        },
    )
    append_edge(
        tenant_id=effective_tenant,
        from_node_id=deployment_node["node_id"],
        to_node_id=decision_node["node_id"],
        edge_type=EDGE_AUTHORIZED_BY,
        metadata={"authorized": bool(authorized), "correlation_id": correlation_id},
    )
    if issue_key:
        jira_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_JIRA_ISSUE,
            ref=str(issue_key),
            payload={"issue_key": issue_key},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=deployment_node["node_id"],
            to_node_id=jira_node["node_id"],
            edge_type=EDGE_RELATED_TO,
        )
    if artifact_digest:
        artifact_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_ARTIFACT,
            ref=str(artifact_digest),
            node_hash=str(artifact_digest),
            payload={"artifact_digest": artifact_digest},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=deployment_node["node_id"],
            to_node_id=artifact_node["node_id"],
            edge_type=EDGE_DERIVED_FROM,
        )
    return {"deployment": deployment_node, "decision": decision_node}


def record_incident_evidence(
    *,
    tenant_id: Optional[str],
    incident_ref: str,
    decision_id: str,
    correlation_id: str,
    deploy_ref: Optional[str],
    issue_key: Optional[str],
    allowed: bool,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_DECISION,
        ref=str(decision_id),
        payload={"decision_id": decision_id},
    )
    incident_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_INCIDENT,
        ref=str(incident_ref),
        payload={"correlation_id": correlation_id, "allowed": bool(allowed), "deploy_ref": deploy_ref},
    )
    append_edge(
        tenant_id=effective_tenant,
        from_node_id=incident_node["node_id"],
        to_node_id=decision_node["node_id"],
        edge_type=EDGE_AUTHORIZED_BY,
        metadata={"allowed": bool(allowed)},
    )
    if deploy_ref:
        deployment_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_DEPLOYMENT,
            ref=str(deploy_ref),
            payload={"deploy_ref": deploy_ref},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=incident_node["node_id"],
            to_node_id=deployment_node["node_id"],
            edge_type=EDGE_RESOLVED_BY,
        )
    if issue_key:
        jira_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_JIRA_ISSUE,
            ref=str(issue_key),
            payload={"issue_key": issue_key},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=incident_node["node_id"],
            to_node_id=jira_node["node_id"],
            edge_type=EDGE_RELATED_TO,
        )
    return {"incident": incident_node, "decision": decision_node}


def record_proof_pack_evidence(
    *,
    tenant_id: Optional[str],
    decision_id: str,
    proof_pack_id: str,
    output_format: str,
    export_checksum: Optional[str],
    checkpoint_id: Optional[str] = None,
    checkpoint_hash: Optional[str] = None,
    graph_hash: Optional[str] = None,
    bundle_version: Optional[str] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_DECISION,
        ref=str(decision_id),
        payload={"decision_id": decision_id},
    )
    artifact_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_ARTIFACT,
        ref=f"proof_pack:{proof_pack_id}",
        node_hash=str(export_checksum or "") or None,
        payload={
            "artifact_type": "PROOF_PACK",
            "proof_pack_id": proof_pack_id,
            "output_format": output_format,
            "bundle_version": bundle_version,
            "graph_hash": graph_hash,
        },
    )
    append_edge(
        tenant_id=effective_tenant,
        from_node_id=decision_node["node_id"],
        to_node_id=artifact_node["node_id"],
        edge_type=EDGE_PRODUCED_ARTIFACT,
        metadata={"proof_pack_id": proof_pack_id},
    )
    result: Dict[str, Any] = {"decision": decision_node, "artifact": artifact_node}

    if checkpoint_id or checkpoint_hash:
        checkpoint_ref = str(checkpoint_id or checkpoint_hash or "")
        checkpoint_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_CHECKPOINT,
            ref=checkpoint_ref,
            node_hash=str(checkpoint_hash or "") or None,
            payload={
                "checkpoint_id": checkpoint_id,
                "checkpoint_hash": checkpoint_hash,
            },
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=decision_node["node_id"],
            to_node_id=checkpoint_node["node_id"],
            edge_type=EDGE_ANCHORED_BY,
            metadata={"checkpoint_id": checkpoint_id},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=artifact_node["node_id"],
            to_node_id=checkpoint_node["node_id"],
            edge_type=EDGE_DERIVED_FROM,
            metadata={"checkpoint_id": checkpoint_id},
        )
        result["checkpoint"] = checkpoint_node

    return result


def record_override_evidence(
    *,
    tenant_id: Optional[str],
    decision_id: Optional[str],
    override_id: str,
    override_hash: Optional[str],
    issue_key: Optional[str],
    repo: Optional[str],
    pr_number: Optional[int],
    reason: Optional[str],
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    override_node = upsert_node(
        tenant_id=effective_tenant,
        node_type=NODE_OVERRIDE,
        ref=str(override_id),
        node_hash=str(override_hash or "") or None,
        payload={
            "issue_key": issue_key,
            "repo": repo,
            "pr_number": pr_number,
            "reason": reason,
        },
    )
    result: Dict[str, Any] = {"override": override_node}
    if decision_id:
        decision_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_DECISION,
            ref=str(decision_id),
            payload={"decision_id": decision_id},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=decision_node["node_id"],
            to_node_id=override_node["node_id"],
            edge_type=EDGE_OVERRIDDEN_BY,
        )
        result["decision"] = decision_node
    if issue_key:
        issue_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_JIRA_ISSUE,
            ref=str(issue_key),
            payload={"issue_key": issue_key},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=override_node["node_id"],
            to_node_id=issue_node["node_id"],
            edge_type=EDGE_RELATED_TO,
        )
        result["jira_issue"] = issue_node
    if repo and pr_number:
        pr_node = upsert_node(
            tenant_id=effective_tenant,
            node_type=NODE_PULL_REQUEST,
            ref=f"{repo}#{pr_number}",
            payload={"repo": repo, "pr_number": pr_number},
        )
        append_edge(
            tenant_id=effective_tenant,
            from_node_id=override_node["node_id"],
            to_node_id=pr_node["node_id"],
            edge_type=EDGE_RELATED_TO,
        )
        result["pull_request"] = pr_node
    return result


def _fetch_edges_for_nodes(*, tenant_id: str, node_ids: Sequence[str]) -> List[Dict[str, Any]]:
    if not node_ids:
        return []
    init_db()
    storage = get_storage_backend()
    placeholders = _placeholder_list(len(node_ids))
    params: List[Any] = [tenant_id, *node_ids, *node_ids]
    rows = storage.fetchall(
        f"""
        SELECT tenant_id, edge_id, from_node_id, to_node_id, type, metadata_json, created_at
        FROM evidence_edges
        WHERE tenant_id = ?
          AND (from_node_id IN ({placeholders}) OR to_node_id IN ({placeholders}))
        ORDER BY created_at ASC
        """,
        params,
    )
    return [_normalise_edge(row) for row in rows]


def _fetch_nodes_by_ids(*, tenant_id: str, node_ids: Iterable[str]) -> List[Dict[str, Any]]:
    node_ids = [str(node_id) for node_id in node_ids if str(node_id)]
    if not node_ids:
        return []
    init_db()
    storage = get_storage_backend()
    placeholders = _placeholder_list(len(node_ids))
    rows = storage.fetchall(
        f"""
        SELECT tenant_id, node_id, type, ref, hash, payload_json, created_at
        FROM evidence_nodes
        WHERE tenant_id = ? AND node_id IN ({placeholders})
        """,
        [tenant_id, *node_ids],
    )
    return [_normalise_node(row) for row in rows]


def get_decision_evidence_graph(
    *,
    tenant_id: Optional[str],
    decision_id: str,
    max_depth: int = 2,
) -> Optional[Dict[str, Any]]:
    effective_tenant = resolve_tenant_id(tenant_id)
    decision_node = _get_node_by_type_ref(
        tenant_id=effective_tenant,
        node_type=NODE_DECISION,
        ref=str(decision_id),
    )
    if not decision_node:
        return None

    visited_nodes: Set[str] = {str(decision_node["node_id"])}
    collected_edges: Dict[str, Dict[str, Any]] = {}
    frontier: Set[str] = {str(decision_node["node_id"])}

    for _ in range(max(1, int(max_depth))):
        edges = _fetch_edges_for_nodes(tenant_id=effective_tenant, node_ids=sorted(frontier))
        next_frontier: Set[str] = set()
        for edge in edges:
            edge_id = str(edge.get("edge_id") or "")
            if edge_id:
                collected_edges[edge_id] = edge
            from_id = str(edge.get("from_node_id") or "")
            to_id = str(edge.get("to_node_id") or "")
            if from_id and from_id not in visited_nodes:
                visited_nodes.add(from_id)
                next_frontier.add(from_id)
            if to_id and to_id not in visited_nodes:
                visited_nodes.add(to_id)
                next_frontier.add(to_id)
        frontier = next_frontier
        if not frontier:
            break

    nodes = _fetch_nodes_by_ids(tenant_id=effective_tenant, node_ids=sorted(visited_nodes))
    edges = sorted(collected_edges.values(), key=_edge_sort_key)
    return {
        "tenant_id": effective_tenant,
        "decision_id": str(decision_id),
        "nodes": sorted(nodes, key=lambda item: (str(item.get("type") or ""), str(item.get("ref") or ""))),
        "edges": edges,
    }


def compute_evidence_graph_hash(graph: Dict[str, Any]) -> str:
    anchors = graph.get("anchors") if isinstance(graph.get("anchors"), dict) else {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    normalized_nodes = sorted(
        (_node_hash_material(node) for node in nodes if isinstance(node, dict)),
        key=canonical_json,
    )
    normalized_edges = sorted(
        (_edge_hash_material(edge) for edge in edges if isinstance(edge, dict)),
        key=canonical_json,
    )
    payload = {
        "decision_id": str(graph.get("decision_id") or ""),
        "anchors": anchors,
        "nodes": normalized_nodes,
        "edges": normalized_edges,
    }
    return sha256_json(payload)


def build_decision_compliance_graph(
    *,
    tenant_id: Optional[str],
    decision_id: str,
    max_depth: int = 3,
    decision_snapshot: Optional[Dict[str, Any]] = None,
    override_snapshot: Optional[Dict[str, Any]] = None,
    checkpoint_snapshot: Optional[Dict[str, Any]] = None,
    chain_proof: Optional[Dict[str, Any]] = None,
    replay_request: Optional[Dict[str, Any]] = None,
    proof_pack_id: Optional[str] = None,
    external_anchor_snapshot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    base_graph = get_decision_evidence_graph(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        max_depth=max_depth,
    ) or {
        "tenant_id": effective_tenant,
        "decision_id": decision_id,
        "nodes": [],
        "edges": [],
    }
    decision_payload = decision_snapshot if isinstance(decision_snapshot, dict) else {}
    override_payload = override_snapshot if isinstance(override_snapshot, dict) else {}
    checkpoint_payload = checkpoint_snapshot if isinstance(checkpoint_snapshot, dict) else {}
    chain_payload = chain_proof if isinstance(chain_proof, dict) else {}
    replay_payload = replay_request if isinstance(replay_request, dict) else {}
    external_anchor_payload = (
        external_anchor_snapshot if isinstance(external_anchor_snapshot, dict) else {}
    )

    checkpoint_ids = checkpoint_payload.get("ids") if isinstance(checkpoint_payload.get("ids"), dict) else {}
    checkpoint_integrity = (
        checkpoint_payload.get("integrity")
        if isinstance(checkpoint_payload.get("integrity"), dict)
        else {}
    )
    checkpoint_signatures = (
        checkpoint_integrity.get("signatures")
        if isinstance(checkpoint_integrity.get("signatures"), dict)
        else {}
    )
    checkpoint_signature = (
        (checkpoint_payload.get("signature") or {}).get("value")
        if isinstance(checkpoint_payload.get("signature"), dict)
        else ""
    )
    anchors = {
        "policy_hash": str(
            decision_payload.get("policy_hash")
            or decision_payload.get("policy_bundle_hash")
            or ""
        ),
        "override_event_id": str(override_payload.get("override_id") or ""),
        "override_event_hash": str(override_payload.get("event_hash") or ""),
        "checkpoint_id": str(checkpoint_ids.get("checkpoint_id") or ""),
        "checkpoint_hash": str(
            checkpoint_integrity.get("checkpoint_hash")
            or checkpoint_payload.get("checkpoint_hash")
            or ""
        ),
        "checkpoint_signature": str(
            checkpoint_signature
            or checkpoint_signatures.get("checkpoint_signature")
            or ""
        ),
        "ledger_tip_hash": str(chain_payload.get("ledger_tip_hash") or ""),
        "proof_pack_id": str(proof_pack_id or ""),
        "replay_endpoint": str(replay_payload.get("endpoint") or ""),
        "external_anchor_provider": str(external_anchor_payload.get("provider") or ""),
        "external_anchor_ref": str(
            external_anchor_payload.get("external_ref")
            or external_anchor_payload.get("anchor_id")
            or ""
        ),
        "external_anchor_root_hash": str(external_anchor_payload.get("root_hash") or ""),
    }
    nodes: List[Dict[str, Any]] = [
        dict(node) for node in (base_graph.get("nodes") or []) if isinstance(node, dict)
    ]
    edges: List[Dict[str, Any]] = [
        dict(edge) for edge in (base_graph.get("edges") or []) if isinstance(edge, dict)
    ]

    def _upsert_virtual_node(
        *,
        node_type: str,
        ref: str,
        node_hash: Optional[str],
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        for node in nodes:
            if str(node.get("type") or "") == node_type and str(node.get("ref") or "") == ref:
                return str(node.get("node_id") or "")
        node_id = f"virtual:{node_type.lower()}:{ref}"
        nodes.append(
            {
                "tenant_id": effective_tenant,
                "node_id": node_id,
                "type": node_type,
                "ref": ref,
                "hash": node_hash,
                "payload": payload or {},
                "created_at": None,
            }
        )
        return node_id

    decision_node_id = _upsert_virtual_node(
        node_type=NODE_DECISION,
        ref=str(decision_id),
        node_hash=str(decision_payload.get("decision_hash") or "") or None,
        payload={"decision_id": decision_id},
    )

    def _append_virtual_edge(
        *,
        from_node_id: str,
        to_node_id: str,
        edge_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        for edge in edges:
            if (
                str(edge.get("from_node_id") or "") == from_node_id
                and str(edge.get("to_node_id") or "") == to_node_id
                and str(edge.get("type") or "") == edge_type
            ):
                return
        edges.append(
            {
                "tenant_id": effective_tenant,
                "edge_id": f"virtual:{edge_type.lower()}:{from_node_id}:{to_node_id}",
                "from_node_id": from_node_id,
                "to_node_id": to_node_id,
                "type": edge_type,
                "metadata": metadata or {},
                "created_at": None,
            }
        )

    checkpoint_ref = anchors["checkpoint_id"] or anchors["checkpoint_hash"]
    if checkpoint_ref:
        checkpoint_node_id = _upsert_virtual_node(
            node_type=NODE_CHECKPOINT,
            ref=checkpoint_ref,
            node_hash=anchors["checkpoint_hash"] or None,
            payload={
                "checkpoint_id": anchors["checkpoint_id"] or None,
                "checkpoint_hash": anchors["checkpoint_hash"] or None,
            },
        )
        _append_virtual_edge(
            from_node_id=decision_node_id,
            to_node_id=checkpoint_node_id,
            edge_type=EDGE_ANCHORED_BY,
            metadata={"checkpoint_id": anchors["checkpoint_id"] or None},
        )

    override_ref = anchors["override_event_id"] or anchors["override_event_hash"]
    if override_ref:
        override_node_id = _upsert_virtual_node(
            node_type=NODE_OVERRIDE,
            ref=override_ref,
            node_hash=anchors["override_event_hash"] or None,
            payload={"override_id": anchors["override_event_id"] or None},
        )
        _append_virtual_edge(
            from_node_id=decision_node_id,
            to_node_id=override_node_id,
            edge_type=EDGE_OVERRIDDEN_BY,
        )

    if anchors["proof_pack_id"]:
        artifact_ref = f"proof_pack:{anchors['proof_pack_id']}"
        artifact_node_id = _upsert_virtual_node(
            node_type=NODE_ARTIFACT,
            ref=artifact_ref,
            node_hash=None,
            payload={
                "artifact_type": "PROOF_PACK",
                "proof_pack_id": anchors["proof_pack_id"],
            },
        )
        _append_virtual_edge(
            from_node_id=decision_node_id,
            to_node_id=artifact_node_id,
            edge_type=EDGE_PRODUCED_ARTIFACT,
            metadata={"proof_pack_id": anchors["proof_pack_id"]},
        )

    if anchors["external_anchor_provider"] and anchors["external_anchor_root_hash"]:
        anchor_ref = (
            anchors["external_anchor_ref"]
            or f"{anchors['external_anchor_provider']}:{anchors['external_anchor_root_hash']}"
        )
        external_anchor_node_id = _upsert_virtual_node(
            node_type=NODE_EXTERNAL_ANCHOR,
            ref=anchor_ref,
            node_hash=anchors["external_anchor_root_hash"] or None,
            payload={
                "provider": anchors["external_anchor_provider"],
                "external_ref": anchors["external_anchor_ref"] or None,
                "root_hash": anchors["external_anchor_root_hash"],
            },
        )
        _append_virtual_edge(
            from_node_id=decision_node_id,
            to_node_id=external_anchor_node_id,
            edge_type=EDGE_ANCHORED_BY,
            metadata={"provider": anchors["external_anchor_provider"]},
        )

    graph_payload = {
        "schema_name": "decision_evidence_graph",
        "schema_version": "v2",
        "tenant_id": effective_tenant,
        "decision_id": decision_id,
        "proof_pack_id": str(proof_pack_id or ""),
        "anchors": anchors,
        "nodes": sorted(nodes, key=lambda item: (str(item.get("type") or ""), str(item.get("ref") or ""))),
        "edges": sorted(edges, key=_edge_sort_key),
    }
    graph_payload["graph_hash"] = compute_evidence_graph_hash(graph_payload)
    return graph_payload


def explain_decision(
    *,
    tenant_id: Optional[str],
    decision_id: str,
) -> Optional[Dict[str, Any]]:
    effective_tenant = resolve_tenant_id(tenant_id)
    graph = get_decision_evidence_graph(
        tenant_id=effective_tenant,
        decision_id=decision_id,
        max_depth=2,
    )
    if not graph:
        return None

    decision_row = AuditReader.get_decision(decision_id, tenant_id=effective_tenant) or {}
    replay_events = list_replay_events(tenant_id=effective_tenant, decision_id=decision_id, limit=5)

    nodes = graph.get("nodes", [])
    policy_nodes = [n for n in nodes if n.get("type") == NODE_POLICY_SNAPSHOT]
    signal_nodes = [n for n in nodes if n.get("type") == NODE_SIGNAL_BUNDLE]
    jira_nodes = [n for n in nodes if n.get("type") == NODE_JIRA_ISSUE]
    pr_nodes = [n for n in nodes if n.get("type") == NODE_PULL_REQUEST]
    deployment_nodes = [n for n in nodes if n.get("type") == NODE_DEPLOYMENT]
    incident_nodes = [n for n in nodes if n.get("type") == NODE_INCIDENT]
    artifact_nodes = [n for n in nodes if n.get("type") == NODE_ARTIFACT]
    override_nodes = [n for n in nodes if n.get("type") == NODE_OVERRIDE]

    status = decision_row.get("release_status") or "UNKNOWN"
    reason_code = ""
    full = decision_row.get("full_decision_json")
    if isinstance(full, str):
        parsed = _json_load(full, {})
    else:
        parsed = full if isinstance(full, dict) else {}
    if isinstance(parsed, dict):
        reason_code = str(parsed.get("reason_code") or "")

    summary_parts = [
        f"Decision {decision_id} returned {status}.",
    ]
    if reason_code:
        summary_parts.append(f"Reason code: {reason_code}.")
    if policy_nodes:
        summary_parts.append(f"Policy snapshot: {policy_nodes[0].get('ref')}.")
    if signal_nodes:
        summary_parts.append(f"Signal bundle hash: {signal_nodes[0].get('hash') or signal_nodes[0].get('ref')}.")
    if jira_nodes:
        summary_parts.append(f"Linked Jira issue: {jira_nodes[0].get('ref')}.")
    if pr_nodes:
        summary_parts.append(f"Linked pull request: {pr_nodes[0].get('ref')}.")
    if replay_events:
        latest_replay = replay_events[0]
        summary_parts.append(
            f"Latest replay {latest_replay.get('replay_id')} match={str(bool(latest_replay.get('match'))).lower()}."
        )
    if artifact_nodes:
        summary_parts.append(f"Artifacts linked: {len(artifact_nodes)}.")
    if override_nodes:
        summary_parts.append(f"Overrides linked: {len(override_nodes)}.")

    return {
        "tenant_id": effective_tenant,
        "decision_id": decision_id,
        "summary": " ".join(summary_parts),
        "decision": {
            "status": status,
            "reason_code": reason_code or None,
            "repo": decision_row.get("repo"),
            "pr_number": decision_row.get("pr_number"),
            "created_at": decision_row.get("created_at"),
        },
        "evidence": {
            "policy_snapshots": policy_nodes,
            "signal_bundles": signal_nodes,
            "jira_issues": jira_nodes,
            "pull_requests": pr_nodes,
            "deployments": deployment_nodes,
            "incidents": incident_nodes,
            "artifacts": artifact_nodes,
            "overrides": override_nodes,
            "replays": replay_events,
        },
        "graph": graph,
    }
