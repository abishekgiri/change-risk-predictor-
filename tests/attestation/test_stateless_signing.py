"""Contract test: DSSE generation must work without a DB backend.

This is the customer-install path — a CI runner with no DB configured,
no writable data/ dir, no infrastructure access.  Signing must complete
and return a valid envelope; persistence is optional and skipped
gracefully when the backend is unreachable.

If this test fails, the customer's Marketplace Action install is broken
in the way the 2026-06-03 readiness audit found: analyze-pr ran but the
DSSE write was never reached because record_release_attestation raised
'unable to open database file'.
"""
from __future__ import annotations

import sqlite3

import pytest

from releasegate.attestation.service import (
    build_attestation_from_bundle,
    build_bundle_from_analysis_result,
    sign_release_attestation,
)
from releasegate.audit.attestations import record_release_attestation
from releasegate.storage import is_storage_unavailable_error


def _bundle():
    """A minimal but realistic decision bundle (mirrors the analyze-pr
    call site shape used in test_decision_id_stability.py)."""
    return build_bundle_from_analysis_result(
        tenant_id="stateless-customer",
        repo="test-org/test-repo",
        pr_number=1,
        commit_sha="abc123def456",
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.10,
        decision="PASS",
        reason_codes=["RISK_LOW_HEURISTIC"],
        signals={"metrics": {"changed_files_count": 1}},
        engine_version="2.0.0",
        timestamp="2026-06-03T00:00:00Z",
    )


# ── Pure stateless signing ──────────────────────────────────────────────────
class TestStatelessSigning:
    def test_sign_without_db_backend(self, monkeypatch):
        """sign_release_attestation returns a valid DSSE envelope when no
        DB env vars are set — the signing key is the only requirement."""
        monkeypatch.delenv("COMPLIANCE_DB_PATH", raising=False)
        monkeypatch.delenv("RELEASEGATE_POSTGRES_DSN", raising=False)
        monkeypatch.delenv("RELEASEGATE_STORAGE_BACKEND", raising=False)

        envelope = sign_release_attestation(_bundle())

        assert envelope is not None
        assert "payload" in envelope
        assert "signatures" in envelope
        assert len(envelope["signatures"]) >= 1
        # DSSE signatures carry the signing bytes
        assert envelope["signatures"][0].get("sig")

    def test_sign_is_deterministic_envelope_shape(self):
        """Two signings of the same bundle yield the same payload (the
        determinism contract from PR #128 — signature bytes may differ
        only if the key changes, which it doesn't here)."""
        e1 = sign_release_attestation(_bundle())
        e2 = sign_release_attestation(_bundle())
        assert e1["payload"] == e2["payload"]


# ── record_release_attestation: persistence is optional ─────────────────────
class TestPersistenceOptional:
    def test_returns_id_when_db_unavailable(self, monkeypatch):
        """When the DB cannot be opened, record_release_attestation must
        still return the derived attestation_id (== normalized
        signed_payload_hash) rather than raising.  This is the exact
        failure the customer Action hit."""
        attestation = build_attestation_from_bundle(_bundle())
        expected_id = attestation["signature"]["signed_payload_hash"].split(":", 1)[-1]

        def _raise_unavailable():
            raise sqlite3.OperationalError("unable to open database file")

        monkeypatch.setattr(
            "releasegate.audit.attestations.init_db", _raise_unavailable
        )

        attestation_id = record_release_attestation(
            decision_id="analysis-test",
            tenant_id="stateless-customer",
            repo="test-org/test-repo",
            pr_number=1,
            attestation=attestation,
        )
        assert attestation_id == expected_id

    def test_genuine_db_error_is_not_swallowed(self, monkeypatch):
        """A real storage error (not an availability problem) must
        propagate — we only skip persistence for 'no backend here',
        never for genuine bugs."""
        attestation = build_attestation_from_bundle(_bundle())

        def _raise_real_error():
            raise ValueError("malformed schema: column does not exist")

        monkeypatch.setattr(
            "releasegate.audit.attestations.init_db", _raise_real_error
        )

        with pytest.raises(ValueError, match="malformed schema"):
            record_release_attestation(
                decision_id="analysis-test",
                tenant_id="stateless-customer",
                repo="test-org/test-repo",
                pr_number=1,
                attestation=attestation,
            )


# ── The storage-unavailability classifier ───────────────────────────────────
class TestStorageUnavailableClassifier:
    @pytest.mark.parametrize(
        "message",
        [
            "unable to open database file",
            "could not connect to server: Connection refused",
            "connection refused",
            "could not translate host name \"db\" to address",
        ],
    )
    def test_classifies_unavailable(self, message):
        assert is_storage_unavailable_error(Exception(message)) is True

    @pytest.mark.parametrize(
        "message",
        [
            "UNIQUE constraint failed: audit_attestations.attestation_id",
            "column foo does not exist",
            "syntax error at or near",
            "malformed schema",
        ],
    )
    def test_does_not_classify_real_errors(self, message):
        assert is_storage_unavailable_error(Exception(message)) is False
