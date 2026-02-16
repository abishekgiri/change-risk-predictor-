from __future__ import annotations

import copy
import hashlib

import pytest

from releasegate.attestation.canonicalize import AttestationContractError, canonicalize_attestation
from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_analysis_result


def _sample_attestation() -> dict:
    bundle = build_bundle_from_analysis_result(
        tenant_id="tenant-test",
        repo="org/service-api",
        pr_number=15,
        commit_sha="5f4dcc3b5aa765d61d8327deb882cf99",
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.85,
        decision="BLOCK",
        reason_codes=["POLICY_BLOCKED"],
        signals={"changed_files": 22, "dependency_provenance": {}},
        engine_version="2.0.0",
        timestamp="2026-02-13T00:00:00Z",
    )
    return build_attestation_from_bundle(bundle)


def _reverse_keys(obj):
    if isinstance(obj, dict):
        return {k: _reverse_keys(obj[k]) for k in reversed(list(obj.keys()))}
    if isinstance(obj, list):
        return [_reverse_keys(item) for item in obj]
    return obj


def test_attestation_canonicalization_is_deterministic_100_runs():
    first = canonicalize_attestation(_sample_attestation())
    first_hash = hashlib.sha256(first).hexdigest()

    for _ in range(100):
        current = canonicalize_attestation(_sample_attestation())
        assert current == first
        assert hashlib.sha256(current).hexdigest() == first_hash


def test_attestation_canonicalization_is_key_order_independent():
    attestation = _sample_attestation()
    reordered = _reverse_keys(attestation)

    first = canonicalize_attestation(attestation)
    second = canonicalize_attestation(reordered)
    assert first == second


def test_attestation_hash_changes_when_value_changes():
    attestation = _sample_attestation()
    tampered = copy.deepcopy(attestation)
    tampered["decision"]["decision"] = "ALLOW"

    base_hash = hashlib.sha256(canonicalize_attestation(attestation)).hexdigest()
    tampered_hash = hashlib.sha256(canonicalize_attestation(tampered)).hexdigest()
    assert tampered_hash != base_hash


def test_attestation_unknown_top_level_field_is_rejected():
    attestation = _sample_attestation()
    attestation["unexpected"] = "field"

    with pytest.raises(AttestationContractError):
        canonicalize_attestation(attestation)

