from __future__ import annotations

import hashlib
import io
import json
import zipfile
from copy import deepcopy

from releasegate.audit.proofpack_v1 import (
    build_proofpack_v1_zip_bytes,
    verify_proofpack_v1_file,
    write_proofpack_v1_zip,
)
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


def _sample_inputs() -> dict:
    return {
        "repo": "org/service-api",
        "pr_number": 15,
        "commit_sha": "5f4dcc3b5aa765d61d8327deb882cf99",
        "policy_hash": "policy-hash",
        "policy_bundle_hash": "policy-bundle-hash",
        "input_snapshot": {"risk": {"level": "HIGH"}, "labels": ["release"]},
    }


def _sample_decision() -> dict:
    return {
        "decision_id": "decision-123",
        "decision": "BLOCK",
        "release_status": "BLOCKED",
        "reason_code": "POLICY_BLOCKED",
        "message": "Policy blocked release",
        "decision_hash": "d" * 64,
        "replay_hash": "e" * 64,
    }


def test_proofpack_v1_is_byte_deterministic_and_ordered():
    attestation = _sample_attestation()
    signature = attestation["signature"]["signature_bytes"]
    inputs = _sample_inputs()
    decision = _sample_decision()

    first = build_proofpack_v1_zip_bytes(
        attestation=attestation,
        signature_text=signature,
        inputs=inputs,
        decision=decision,
        created_by="2.0.0",
    )

    # Reorder keys intentionally; canonicalization should keep byte output stable.
    inputs_reordered = {k: inputs[k] for k in reversed(list(inputs.keys()))}
    decision_reordered = {k: decision[k] for k in reversed(list(decision.keys()))}
    second = build_proofpack_v1_zip_bytes(
        attestation=deepcopy(attestation),
        signature_text=signature,
        inputs=inputs_reordered,
        decision=decision_reordered,
        created_by="2.0.0",
    )

    assert first == second
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()

    with zipfile.ZipFile(io.BytesIO(first), "r") as zf:
        names = zf.namelist()
        assert names == [
            "attestation.json",
            "signature.txt",
            "inputs.json",
            "decision.json",
            "manifest.json",
        ]
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest["proofpack_version"] == "v1"
        assert [f["path"] for f in manifest["files"]] == [
            "attestation.json",
            "signature.txt",
            "inputs.json",
            "decision.json",
        ]


def test_proofpack_v1_hash_changes_on_decision_mutation():
    attestation = _sample_attestation()
    signature = attestation["signature"]["signature_bytes"]
    inputs = _sample_inputs()
    decision = _sample_decision()

    base = build_proofpack_v1_zip_bytes(
        attestation=attestation,
        signature_text=signature,
        inputs=inputs,
        decision=decision,
        created_by="2.0.0",
    )
    mutated = dict(decision)
    mutated["reason_code"] = "POLICY_ALLOWED"
    changed = build_proofpack_v1_zip_bytes(
        attestation=attestation,
        signature_text=signature,
        inputs=inputs,
        decision=mutated,
        created_by="2.0.0",
    )
    assert hashlib.sha256(base).hexdigest() != hashlib.sha256(changed).hexdigest()


def test_verify_proofpack_v1_pass_and_tamper_fail(tmp_path):
    attestation = _sample_attestation()
    output = tmp_path / "proofpack.zip"
    write_proofpack_v1_zip(
        out_path=str(output),
        attestation=attestation,
        signature_text=attestation["signature"]["signature_bytes"],
        inputs=_sample_inputs(),
        decision=_sample_decision(),
        created_by="2.0.0",
    )

    report = verify_proofpack_v1_file(str(output))
    assert report["ok"] is True

    with zipfile.ZipFile(output, "r") as zf:
        names = zf.namelist()
        blobs = {name: zf.read(name) for name in names}

    tampered_decision = json.loads(blobs["decision.json"].decode("utf-8"))
    tampered_decision["reason_code"] = "POLICY_ALLOWED"
    blobs["decision.json"] = json.dumps(tampered_decision, separators=(",", ":"), sort_keys=True).encode("utf-8")

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in names:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            zf.writestr(info, blobs[name])

    tampered_report = verify_proofpack_v1_file(str(output))
    assert tampered_report["ok"] is False
    assert tampered_report["error_code"] == "FILE_HASH_MISMATCH"


def test_verify_proofpack_rejects_partial_rfc3161_artifacts(tmp_path):
    attestation = _sample_attestation()
    output = tmp_path / "proofpack-rfc.zip"
    write_proofpack_v1_zip(
        out_path=str(output),
        attestation=attestation,
        signature_text=attestation["signature"]["signature_bytes"],
        inputs=_sample_inputs(),
        decision=_sample_decision(),
        created_by="2.0.0",
        timestamp_metadata={
            "format": "rfc3161",
            "hash_alg": "sha256",
            "payload_hash": attestation["signature"]["signed_payload_hash"],
            "generated_at": "2026-02-13T00:00:00Z",
            "token_sha256": "sha256:" + ("0" * 64),
        },
    )

    report = verify_proofpack_v1_file(str(output))
    assert report["ok"] is False
    assert report["error_code"] == "RFC3161_ARTIFACT_INVALID"
