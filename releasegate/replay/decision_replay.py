from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from releasegate.decision.types import Decision, DecisionType
from releasegate.enforcement.types import ControlContext
from releasegate.engine import ComplianceEngine


def _hash_policy_bindings(bindings: List[Dict[str, Any]]) -> str:
    if not bindings:
        return hashlib.sha256(b"[]").hexdigest()
    material = []
    for b in sorted(bindings, key=lambda x: x.get("policy_id", "")):
        material.append(
            {
                "policy_id": b.get("policy_id"),
                "policy_version": b.get("policy_version"),
                "policy_hash": b.get("policy_hash"),
            }
        )
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _flatten_runtime_signals(engine: ComplianceEngine, raw_signals: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the same flattened signal map shape used by ComplianceEngine.evaluate().
    """
    normalized = dict(raw_signals)
    normalized.setdefault("diff", {})
    normalized.setdefault("labels", [])
    normalized.setdefault("files_changed", [])
    normalized.setdefault("total_churn", 0)
    normalized.setdefault("commits", [])
    normalized.setdefault("critical_paths", [])
    normalized.setdefault("dependency_changes", [])
    normalized.setdefault("secrets_findings", [])
    normalized.setdefault("licenses", [])

    core_output = engine.core_risk.evaluate(normalized)
    phase3_signals: Dict[str, Any] = {}

    if "diff" in normalized:
        context = ControlContext(
            repo=normalized.get("repo", "unknown"),
            pr_number=normalized.get("pr_number", 0),
            diff=normalized.get("diff") or {},
            config=engine.config,
            provider=normalized.get("provider"),
        )
        registry_result = engine.control_registry.run_all(context)
        phase3_signals = registry_result.get("signals", {}) if isinstance(registry_result, dict) else {}

    return engine._flatten_signals(
        {
            "core_risk": core_output,
            "features": core_output.get("signals", {}),
            "raw": normalized,
            **phase3_signals,
        }
    )


def replay_decision(decision: Decision) -> Dict[str, Any]:
    """
    Re-evaluate a decision using its stored input snapshot + bound policy snapshots.
    """
    input_snapshot = decision.input_snapshot or {}
    raw_signals = input_snapshot.get("signal_map")
    policies_requested = input_snapshot.get("policies_requested", [])

    if not isinstance(raw_signals, dict):
        raise ValueError("Decision snapshot missing `signal_map`")
    if not decision.policy_bindings:
        raise ValueError("Decision has no policy bindings")

    engine = ComplianceEngine({})
    signals = _flatten_runtime_signals(engine, raw_signals)

    by_id = {binding.policy_id: binding for binding in decision.policy_bindings}
    unresolved_policy_ids = [pid for pid in policies_requested if pid not in by_id]
    relevant_ids = [pid for pid in policies_requested if pid in by_id] if policies_requested else sorted(by_id.keys())

    final_status = DecisionType.ALLOWED
    triggered_policies: List[str] = []
    requirements: List[str] = []

    for policy_id in relevant_ids:
        binding = by_id[policy_id]
        policy = binding.policy or {}
        controls = policy.get("controls") or []
        if not controls:
            continue

        matched_conditions: List[str] = []
        for ctrl in controls:
            signal_name = ctrl.get("signal")
            operator = ctrl.get("operator")
            expected = ctrl.get("value")
            actual = signals.get(signal_name)
            if engine._check_condition(actual, operator, expected):
                matched_conditions.append(f"{signal_name} ({actual}) {operator} {expected}")

        if len(matched_conditions) != len(controls):
            continue

        triggered_policies.append(policy_id)
        requirements.extend(matched_conditions)

        enforcement = policy.get("enforcement") or {}
        result = str(enforcement.get("result") or "COMPLIANT").upper()
        if result == "BLOCK":
            final_status = DecisionType.BLOCKED
        elif result == "WARN" and final_status != DecisionType.BLOCKED:
            final_status = DecisionType.CONDITIONAL

    replay_hash = _hash_policy_bindings([by_id[pid].model_dump(mode="json") for pid in relevant_ids])
    original_status = decision.release_status

    return {
        "decision_id": decision.decision_id,
        "tenant_id": decision.tenant_id,
        "replayed_at": datetime.now(timezone.utc).isoformat(),
        "original_status": original_status.value,
        "replay_status": final_status.value,
        "status_match": original_status == final_status,
        "policy_hash_original": decision.policy_bundle_hash,
        "policy_hash_replay": replay_hash,
        "policy_hash_match": decision.policy_bundle_hash == replay_hash,
        "triggered_policies": triggered_policies,
        "requirements": requirements,
        "unresolved_policy_ids": unresolved_policy_ids,
        "inputs_present": decision.inputs_present,
    }
