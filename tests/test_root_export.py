from __future__ import annotations

from releasegate.attestation.crypto import load_root_private_key_from_env, public_key_pem_from_private
from releasegate.audit.root_export import (
    DailyRootRow,
    build_external_root_payload,
    sign_external_root_payload,
    verify_external_root_payload,
)


def _sample_row() -> DailyRootRow:
    return DailyRootRow(
        date_utc="2026-02-13",
        leaf_count=128,
        root_hash="sha256:abc123",
        computed_at="2026-02-14T00:30:00Z",
        engine_git_sha="deadbeef",
        engine_version="2.1.0",
    )


def test_root_payload_contains_required_fields():
    payload = build_external_root_payload(_sample_row())
    assert payload["root_version"] == "1"
    assert payload["date_utc"] == "2026-02-13"
    assert payload["leaf_count"] == 128
    assert payload["root_hash"] == "sha256:abc123"
    assert payload["computed_at"] == "2026-02-14T00:30:00Z"
    assert "engine_build" in payload
    assert payload["engine_build"]["git_sha"] == "deadbeef"
    assert payload["engine_build"]["version"] == "2.1.0"


def test_signed_root_contains_signature_metadata(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ROOT_KEY_ID", "rg-root-test-2026-01")
    signed = sign_external_root_payload(build_external_root_payload(_sample_row()))
    assert "signature" in signed
    assert signed["signature"]["alg"] == "ed25519"
    assert signed["signature"]["root_key_id"] == "rg-root-test-2026-01"
    assert isinstance(signed["signature"]["sig"], str) and signed["signature"]["sig"]


def test_signing_is_deterministic_for_same_payload(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ROOT_KEY_ID", "rg-root-test-2026-01")
    payload = build_external_root_payload(_sample_row())
    first = sign_external_root_payload(payload)
    second = sign_external_root_payload(payload)
    assert first == second


def test_verify_external_root_payload_roundtrip(monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ROOT_KEY_ID", "rg-root-test-2026-01")
    payload = build_external_root_payload(_sample_row())
    signed = sign_external_root_payload(payload)
    root_public = public_key_pem_from_private(load_root_private_key_from_env())
    assert verify_external_root_payload(signed, root_public) is True
