from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.decision.hashing import (
    compute_decision_hash,
    compute_input_hash,
    compute_policy_hash_from_bindings,
    compute_replay_hash,
)
from releasegate.decision.types import Decision, DecisionType
from releasegate.enforcement.types import ControlContext
from releasegate.engine import ComplianceEngine
from releasegate.utils.canonical import sha256_json


def _current_engine_version() -> str:
    return str(os.getenv("RELEASEGATE_ENGINE_VERSION", "0.2.0")).strip() or "0.2.0"


def _reason_code_for_status(status: DecisionType) -> str:
    if status == DecisionType.BLOCKED:
        return "POLICY_BLOCKED"
    if status == DecisionType.CONDITIONAL:
        return "POLICY_CONDITIONAL"
    if status == DecisionType.ERROR:
        return "SYSTEM_ERROR"
    if status == DecisionType.SKIPPED:
        return "POLICY_SKIPPED"
    return "POLICY_ALLOWED"


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


def _bindings_from_policy_snapshot(policy_snapshot: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(policy_snapshot, dict):
        return []
    resolved_policy = policy_snapshot.get("resolved_policy")
    if not isinstance(resolved_policy, dict):
        return []
    raw_bindings = resolved_policy.get("policy_bindings")
    if not isinstance(raw_bindings, list):
        return []

    normalized: List[Dict[str, Any]] = []
    for entry in raw_bindings:
        if not isinstance(entry, dict):
            continue
        policy_id = str(entry.get("policy_id") or "").strip()
        if not policy_id:
            continue
        normalized.append(
            {
                "policy_id": policy_id,
                "policy_version": str(entry.get("policy_version") or "1").strip() or "1",
                "policy_hash": str(entry.get("policy_hash") or "").strip(),
                "policy": entry.get("policy") if isinstance(entry.get("policy"), dict) else {},
            }
        )
    return normalized


def _bindings_from_decision(decision: Decision) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for binding in decision.policy_bindings:
        payload = binding.model_dump(mode="json")
        normalized.append(
            {
                "policy_id": str(payload.get("policy_id") or "").strip(),
                "policy_version": str(payload.get("policy_version") or "1").strip() or "1",
                "policy_hash": str(payload.get("policy_hash") or "").strip(),
                "policy": payload.get("policy") if isinstance(payload.get("policy"), dict) else {},
            }
        )
    return [entry for entry in normalized if entry["policy_id"]]


def _output_hash(
    *,
    status: str,
    reason_code: Optional[str],
) -> str:
    return sha256_json(
        {
            "status": str(status),
            "reason_code": str(reason_code or ""),
        }
    )


def _append_diff(diffs: List[Dict[str, Any]], path: str, old: Any, new: Any) -> None:
    if old == new:
        return
    diffs.append({"path": path, "old": old, "new": new})


def replay_decision(
    decision: Decision,
    *,
    policy_snapshot: Optional[Dict[str, Any]] = None,
    stored_engine_version: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Re-evaluate a decision using stored canonical input snapshot + policy snapshot.
    """
    input_snapshot = decision.input_snapshot or {}
    raw_signals = input_snapshot.get("signal_map")
    policies_requested = input_snapshot.get("policies_requested", [])

    if not isinstance(raw_signals, dict):
        raise ValueError("Decision snapshot missing `signal_map`")
    binding_entries = _bindings_from_policy_snapshot(policy_snapshot) or _bindings_from_decision(decision)
    if not binding_entries:
        raise ValueError("Decision has no policy bindings")

    engine = ComplianceEngine({})
    signals = _flatten_runtime_signals(engine, raw_signals)

    by_id = {entry["policy_id"]: entry for entry in binding_entries}
    unresolved_policy_ids = [pid for pid in policies_requested if pid not in by_id]
    relevant_ids = [pid for pid in policies_requested if pid in by_id] if policies_requested else sorted(by_id.keys())

    final_status = DecisionType.ALLOWED
    triggered_policies: List[str] = []
    requirements: List[str] = []

    for policy_id in relevant_ids:
        binding = by_id[policy_id]
        policy = binding.get("policy") or {}
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

    replay_policy_hash = compute_policy_hash_from_bindings([by_id[pid] for pid in relevant_ids])
    replay_reason_code = _reason_code_for_status(final_status)
    replay_decision_hash = compute_decision_hash(
        release_status=final_status.value,
        reason_code=replay_reason_code,
        policy_bundle_hash=replay_policy_hash,
        inputs_present=decision.inputs_present,
    )
    replay_input_hash = compute_input_hash(decision.input_snapshot)
    replay_replay_hash = compute_replay_hash(
        input_hash=replay_input_hash,
        policy_hash=replay_policy_hash,
        decision_hash=replay_decision_hash,
    )

    original_input_hash = decision.input_hash or compute_input_hash(decision.input_snapshot)
    original_policy_hash = decision.policy_hash or decision.policy_bundle_hash
    original_decision_hash = decision.decision_hash or compute_decision_hash(
        release_status=decision.release_status.value,
        reason_code=decision.reason_code,
        policy_bundle_hash=original_policy_hash,
        inputs_present=decision.inputs_present,
    )
    original_replay_hash = decision.replay_hash or compute_replay_hash(
        input_hash=original_input_hash,
        policy_hash=original_policy_hash,
        decision_hash=original_decision_hash,
    )

    input_hash_match = original_input_hash == replay_input_hash
    policy_hash_match = original_policy_hash == replay_policy_hash
    decision_hash_match = original_decision_hash == replay_decision_hash
    replay_hash_match = original_replay_hash == replay_replay_hash
    mismatch_reasons: List[str] = []
    if not input_hash_match:
        mismatch_reasons.append("input drift")
    if not policy_hash_match:
        mismatch_reasons.append("policy drift")
    if not decision_hash_match:
        mismatch_reasons.append("non-deterministic decision output")
    if not replay_hash_match:
        mismatch_reasons.append("replay hash mismatch")

    original_status = decision.release_status
    original_reason_code = decision.reason_code
    original_output_hash = _output_hash(
        status=original_status.value,
        reason_code=original_reason_code,
    )
    replay_output_hash = _output_hash(
        status=final_status.value,
        reason_code=replay_reason_code,
    )
    replay_engine_version = _current_engine_version()
    old_engine_version = str(stored_engine_version or "")

    diffs: List[Dict[str, Any]] = []
    _append_diff(diffs, "/status", original_status.value, final_status.value)
    _append_diff(diffs, "/reason_code", original_reason_code, replay_reason_code)
    _append_diff(diffs, "/policy_hash", original_policy_hash, replay_policy_hash)
    _append_diff(diffs, "/input_hash", original_input_hash, replay_input_hash)
    _append_diff(diffs, "/decision_hash", original_decision_hash, replay_decision_hash)
    _append_diff(diffs, "/replay_hash", original_replay_hash, replay_replay_hash)
    _append_diff(diffs, "/output_hash", original_output_hash, replay_output_hash)
    if old_engine_version:
        _append_diff(diffs, "/engine_version", old_engine_version, replay_engine_version)

    matches_original = input_hash_match and policy_hash_match and decision_hash_match and replay_hash_match and not diffs
    if not matches_original and not mismatch_reasons:
        mismatch_reasons.append("deterministic replay mismatch")

    return {
        "decision_id": decision.decision_id,
        "tenant_id": decision.tenant_id,
        "replayed_at": datetime.now(timezone.utc).isoformat(),
        "original_status": original_status.value,
        "replay_status": final_status.value,
        "status_match": original_status == final_status,
        "policy_hash_original": original_policy_hash,
        "policy_hash_replay": replay_policy_hash,
        "policy_hash_match": policy_hash_match,
        "input_hash_original": original_input_hash,
        "input_hash_replay": replay_input_hash,
        "input_hash_match": input_hash_match,
        "decision_hash_original": original_decision_hash,
        "decision_hash_replay": replay_decision_hash,
        "decision_hash_match": decision_hash_match,
        "replay_hash_original": original_replay_hash,
        "replay_hash_replay": replay_replay_hash,
        "replay_hash_match": replay_hash_match,
        "matches_original": matches_original,
        "match": matches_original,
        "mismatch_reason": ", ".join(mismatch_reasons) if mismatch_reasons else None,
        "triggered_policies": triggered_policies,
        "requirements": requirements,
        "unresolved_policy_ids": unresolved_policy_ids,
        "inputs_present": decision.inputs_present,
        "diff": diffs,
        "old": {
            "policy_hash": original_policy_hash,
            "engine_version": old_engine_version,
            "output_hash": original_output_hash,
            "status": original_status.value,
            "reason_code": original_reason_code,
            "input_hash": original_input_hash,
            "decision_hash": original_decision_hash,
            "replay_hash": original_replay_hash,
        },
        "new": {
            "policy_hash": replay_policy_hash,
            "engine_version": replay_engine_version,
            "output_hash": replay_output_hash,
            "status": final_status.value,
            "reason_code": replay_reason_code,
            "input_hash": replay_input_hash,
            "decision_hash": replay_decision_hash,
            "replay_hash": replay_replay_hash,
        },
        "engine_version_original": old_engine_version,
        "engine_version_replay": replay_engine_version,
        "output_hash_original": original_output_hash,
        "output_hash_replay": replay_output_hash,
        "output_hash_match": original_output_hash == replay_output_hash,
    }
