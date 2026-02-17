from __future__ import annotations

import json

from releasegate.attestation.crypto import current_key_id, load_private_key_from_env
from releasegate.attestation.dsse import wrap_dsse
from releasegate.attestation.intoto import build_intoto_statement
from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_analysis_result
from releasegate.cli import main


def _sample_dsse_envelope() -> dict:
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
        signals={"changed_files": 22},
        engine_version="2.0.0",
        timestamp="2026-02-13T00:00:00Z",
    )
    attestation = build_attestation_from_bundle(bundle)
    statement = build_intoto_statement(attestation)
    return wrap_dsse(statement, signing_key=load_private_key_from_env(), key_id=current_key_id())


def test_log_dsse_and_verify_log_roundtrip(monkeypatch, tmp_path):
    envelope = _sample_dsse_envelope()
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text(json.dumps(envelope), encoding="utf-8")

    log_path = tmp_path / "attestations.log"

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "log-dsse",
            "--dsse",
            str(dsse_path),
            "--log",
            str(log_path),
            "--format",
            "json",
        ],
    )
    assert main() == 0

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-log",
            "--dsse",
            str(dsse_path),
            "--log",
            str(log_path),
            "--format",
            "json",
        ],
    )
    assert main() == 0


def test_verify_log_fails_when_dsse_changes(monkeypatch, tmp_path):
    envelope = _sample_dsse_envelope()
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text(json.dumps(envelope), encoding="utf-8")

    log_path = tmp_path / "attestations.log"

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "log-dsse",
            "--dsse",
            str(dsse_path),
            "--log",
            str(log_path),
            "--format",
            "json",
        ],
    )
    assert main() == 0

    # Tamper the DSSE envelope without updating the log.
    tampered = dict(envelope)
    tampered["payload"] = ("A" if tampered["payload"][:1] != "A" else "B") + tampered["payload"][1:]
    dsse_path.write_text(json.dumps(tampered), encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-log",
            "--dsse",
            str(dsse_path),
            "--log",
            str(log_path),
            "--format",
            "json",
        ],
    )
    assert main() == 2

