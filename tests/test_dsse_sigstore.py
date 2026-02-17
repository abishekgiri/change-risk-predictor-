from __future__ import annotations

import json

import pytest

from releasegate.attestation.dsse import SigstoreSigningError, verify_dsse_sigstore, wrap_dsse_sigstore


def test_wrap_dsse_sigstore_fails_closed_when_cosign_missing(monkeypatch, tmp_path):
    def _raise(*args, **kwargs):
        raise FileNotFoundError("cosign")

    import releasegate.attestation.dsse as dsse_mod

    monkeypatch.setattr(dsse_mod.subprocess, "run", _raise)

    bundle_path = tmp_path / "bundle.json"
    with pytest.raises(SigstoreSigningError) as exc:
        wrap_dsse_sigstore({"_type": "https://in-toto.io/Statement/v1"}, bundle_path=str(bundle_path))
    assert "cosign not found" in str(exc.value).lower()


def test_verify_dsse_sigstore_reports_cosign_not_found(monkeypatch, tmp_path):
    def _raise(*args, **kwargs):
        raise FileNotFoundError("cosign")

    import releasegate.attestation.dsse as dsse_mod

    monkeypatch.setattr(dsse_mod.subprocess, "run", _raise)

    payload = {"_type": "https://in-toto.io/Statement/v1"}
    env = wrap_dsse_sigstore.__wrapped__ if hasattr(wrap_dsse_sigstore, "__wrapped__") else None
    # Build a minimal DSSE envelope without calling cosign; signature verification is handled by verify_dsse_sigstore.
    envelope = {
        "payloadType": dsse_mod.DSSE_PAYLOAD_TYPE,
        "payload": dsse_mod.base64.b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")).decode("ascii"),
        "signatures": [{"keyid": "sigstore", "sig": "AA=="}],
    }

    ok, decoded, error = verify_dsse_sigstore(envelope, bundle_path=str(tmp_path / "bundle.json"))
    assert ok is False
    assert decoded is None
    assert error == "COSIGN_NOT_FOUND"

