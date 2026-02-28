from __future__ import annotations

from copy import deepcopy

from releasegate.evidence.graph import compute_evidence_graph_hash


def _graph_payload() -> dict:
    return {
        "decision_id": "decision-1",
        "anchors": {
            "policy_hash": "policy-hash-1",
            "override_event_hash": "override-hash-1",
            "checkpoint_hash": "checkpoint-hash-1",
            "ledger_tip_hash": "ledger-hash-1",
        },
        "nodes": [
            {"type": "DECISION", "ref": "decision-1", "hash": "decision-hash", "payload": {}},
            {"type": "POLICY_SNAPSHOT", "ref": "snapshot-1", "hash": "policy-hash-1", "payload": {}},
        ],
        "edges": [
            {
                "type": "USED_POLICY",
                "from_node_id": "node-decision",
                "to_node_id": "node-policy",
                "metadata": {},
            }
        ],
    }


def test_graph_hash_is_deterministic_with_reordered_nodes_and_edges():
    graph_a = _graph_payload()
    graph_b = deepcopy(graph_a)
    graph_b["nodes"] = list(reversed(graph_b["nodes"]))
    graph_b["edges"] = list(reversed(graph_b["edges"]))

    assert compute_evidence_graph_hash(graph_a) == compute_evidence_graph_hash(graph_b)


def test_graph_hash_changes_when_override_anchor_changes():
    graph_a = _graph_payload()
    graph_b = deepcopy(graph_a)
    graph_b["anchors"]["override_event_hash"] = "override-hash-2"

    assert compute_evidence_graph_hash(graph_a) != compute_evidence_graph_hash(graph_b)


def test_graph_hash_changes_when_policy_anchor_changes():
    graph_a = _graph_payload()
    graph_b = deepcopy(graph_a)
    graph_b["anchors"]["policy_hash"] = "policy-hash-2"

    assert compute_evidence_graph_hash(graph_a) != compute_evidence_graph_hash(graph_b)
