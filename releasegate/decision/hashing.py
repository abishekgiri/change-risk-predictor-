from __future__ import annotations

from typing import Any, Dict, Iterable

from releasegate.utils.canonical import canonical_json, sha256_json, sha256_text

NON_DETERMINISTIC_INPUT_KEYS = {
    "computed_at",
    "generated_at",
}


def _policy_binding_material(bindings: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    material: list[Dict[str, Any]] = []
    for binding in bindings:
        material.append(
            {
                "policy_id": binding.get("policy_id"),
                "policy_version": binding.get("policy_version"),
                "policy_hash": binding.get("policy_hash"),
            }
        )
    material.sort(key=lambda x: (x.get("policy_id") or "", x.get("policy_version") or ""))
    return material


def _normalize_input_snapshot(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for key, item in value.items():
            if str(key) in NON_DETERMINISTIC_INPUT_KEYS:
                continue
            normalized[key] = _normalize_input_snapshot(item)
        return normalized
    if isinstance(value, list):
        return [_normalize_input_snapshot(item) for item in value]
    return value


def compute_input_hash(input_snapshot: Dict[str, Any] | None) -> str:
    # Exclude non-deterministic envelope timestamps from decision determinism.
    return sha256_json(_normalize_input_snapshot(input_snapshot or {}))


def compute_policy_hash_from_bindings(bindings: Iterable[Dict[str, Any]]) -> str:
    return sha256_json(_policy_binding_material(bindings))


def decision_payload_for_hash(
    *,
    release_status: str,
    reason_code: str | None,
    policy_bundle_hash: str,
    inputs_present: Dict[str, Any] | None,
) -> Dict[str, Any]:
    return {
        "release_status": str(release_status),
        "reason_code": str(reason_code or ""),
        "policy_bundle_hash": str(policy_bundle_hash or ""),
        "inputs_present": inputs_present or {},
    }


def compute_decision_hash(
    *,
    release_status: str,
    reason_code: str | None,
    policy_bundle_hash: str,
    inputs_present: Dict[str, Any] | None,
) -> str:
    payload = decision_payload_for_hash(
        release_status=release_status,
        reason_code=reason_code,
        policy_bundle_hash=policy_bundle_hash,
        inputs_present=inputs_present,
    )
    return sha256_json(payload)


def compute_replay_hash(*, input_hash: str, policy_hash: str, decision_hash: str) -> str:
    payload = {
        "input_hash": input_hash,
        "policy_hash": policy_hash,
        "decision_hash": decision_hash,
    }
    return sha256_text(canonical_json(payload))
