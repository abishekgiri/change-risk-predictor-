from __future__ import annotations

import base64
import json

import pytest

from releasegate.attestation.crypto import (
    current_key_id,
    load_private_key_from_env,
    public_key_pem_from_private,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releasegate.attestation.dsse import wrap_dsse, wrap_dsse_multi
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


@pytest.fixture
def key_map_file(tmp_path) -> str:
    key_id = current_key_id()
    public_key = public_key_pem_from_private(load_private_key_from_env())
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({key_id: public_key}), encoding="utf-8")
    return str(path)


def test_verify_dsse_cli_ok(monkeypatch, tmp_path, key_map_file):
    envelope = _sample_dsse_envelope()
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text(json.dumps(envelope), encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-dsse",
            "--dsse",
            str(dsse_path),
            "--key-file",
            key_map_file,
            "--require-keyid",
            current_key_id(),
            "--format",
            "json",
        ],
    )
    assert main() == 0


def test_verify_dsse_cli_pinned_keyid_mismatch_fails(monkeypatch, tmp_path, key_map_file, capsys):
    envelope = _sample_dsse_envelope()
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text(json.dumps(envelope), encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-dsse",
            "--dsse",
            str(dsse_path),
            "--key-file",
            key_map_file,
            "--require-keyid",
            "unexpected-keyid",
            "--format",
            "json",
        ],
    )
    assert main() == 2
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["error_code"] == "KEYID_PIN_MISMATCH"


def test_verify_dsse_cli_tamper_fails(monkeypatch, tmp_path, key_map_file):
    envelope = _sample_dsse_envelope()
    envelope["payload"] = ("A" if envelope["payload"][:1] != "A" else "B") + envelope["payload"][1:]
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text(json.dumps(envelope), encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-dsse",
            "--dsse",
            str(dsse_path),
            "--key-file",
            key_map_file,
            "--require-keyid",
            current_key_id(),
            "--format",
            "json",
        ],
    )
    assert main() == 2


def test_verify_dsse_cli_invalid_json_is_format_error(monkeypatch, tmp_path, key_map_file):
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text("{not json", encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-dsse",
            "--dsse",
            str(dsse_path),
            "--key-file",
            key_map_file,
            "--format",
            "json",
        ],
    )
    assert main() == 3


def test_verify_dsse_cli_conformance_mismatch_is_format_error(monkeypatch, tmp_path, key_map_file):
    envelope = _sample_dsse_envelope()
    # Rebuild a signed envelope with an invalid statement type (still signature-valid).
    statement = json.loads(base64.b64decode(envelope["payload"].encode("ascii"), validate=True).decode("utf-8"))
    statement["_type"] = "https://example.invalid/Statement/v1"

    envelope = wrap_dsse(statement, signing_key=load_private_key_from_env(), key_id=current_key_id())
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text(json.dumps(envelope), encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-dsse",
            "--dsse",
            str(dsse_path),
            "--key-file",
            key_map_file,
            "--require-keyid",
            current_key_id(),
            "--format",
            "json",
        ],
    )
    assert main() == 3


def test_verify_dsse_cli_keymap_missing_keyid_fails(monkeypatch, tmp_path, capsys):
    envelope = _sample_dsse_envelope()
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text(json.dumps(envelope), encoding="utf-8")

    wrong_keys_path = tmp_path / "wrong_keys.json"
    wrong_keys_path.write_text(json.dumps({"some-other-key": "fake"}), encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-dsse",
            "--dsse",
            str(dsse_path),
            "--key-file",
            str(wrong_keys_path),
            "--format",
            "json",
        ],
    )
    assert main() == 2
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["error_code"] == "KEYID_NOT_FOUND"


def test_verify_dsse_cli_requires_multiple_signers(monkeypatch, tmp_path, capsys):
    envelope = _sample_dsse_envelope()
    statement = json.loads(base64.b64decode(envelope["payload"].encode("ascii"), validate=True).decode("utf-8"))

    key1 = load_private_key_from_env()
    key2 = Ed25519PrivateKey.generate()
    kid1 = current_key_id()
    kid2 = "rg-test-secondary"

    envelope = wrap_dsse_multi(statement, signers=[(kid1, key1), (kid2, key2)])
    dsse_path = tmp_path / "env.dsse.json"
    dsse_path.write_text(json.dumps(envelope), encoding="utf-8")

    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({kid1: public_key_pem_from_private(key1), kid2: public_key_pem_from_private(key2)}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "releasegate",
            "verify-dsse",
            "--dsse",
            str(dsse_path),
            "--key-file",
            str(keys_path),
            "--require-signers",
            f"{kid1},{kid2}",
            "--format",
            "json",
        ],
    )
    assert main() == 0
