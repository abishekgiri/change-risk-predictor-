"""Per-run uniqueness contract for `attestation_id`.

Background (PR landed after v2.2.0):
  `decision_id` is deterministic post-#128 — same PR + same commit + same
  policy → same id.  But the empirical PR #125 demo found that
  `attestation_id` was *also* deterministic (collapsed to the first-stored
  row) because:
    1. `_attestation_id() = signed_payload_hash` (per-run unique by
       definition — each CI run signs a different DSSE payload).
    2. `record_release_attestation()` looked up `(tenant_id, decision_id)`
       first and short-circuited on existing rows, returning the
       originally-stored id.
    3. A `(tenant_id, decision_id)` UNIQUE index forced one row per
       logical decision.

  All three were removed in this change.  Going forward,
  `audit_attestations` accumulates one row per signing event, so each
  CI invocation has its own per-run audit envelope — while
  `decision_id` continues to be deterministic across re-runs.

These tests pin down the new contract end-to-end against the SQLite
storage backend.
"""
from __future__ import annotations

import json
import os
import sqlite3

import pytest

from releasegate.attestation.service import (
    build_attestation_from_bundle,
    build_bundle_from_analysis_result,
)
from releasegate.audit.attestations import record_release_attestation
from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db


# ── Fixture: clean DB per test (matches tests/test_transparency_log.py) ────
@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


# ── Helpers ─────────────────────────────────────────────────────────────────
def _build_for_run(*, run_id: str, run_attempt: str = "1"):
    """Mirror the analyze-pr CI call site shape.  Same PR/commit/policy
    inputs; only the workflow_run identifiers vary, which is the real
    drift source between two CI invocations of the same PR.
    """
    return build_bundle_from_analysis_result(
        tenant_id="tenant-test",
        repo="org/service-api",
        pr_number=125,
        commit_sha="abc123def456",
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.10,
        decision="PASS",
        reason_codes=["RISK_LOW_HEURISTIC"],
        signals={
            "metrics": {"changed_files_count": 1, "additions": 1, "deletions": 0, "total_churn": 1},
            "dependency_provenance": {"satisfied": True},
            "source_ref": "refs/pull/125/merge",
            "workflow_run": {
                "provider": "github-actions",
                "repository": "org/service-api",
                "workflow": "Compliance Check",
                "run_id": run_id,
                "run_attempt": run_attempt,
                "actor": "alice",
                "job": "compliance",
                "ref": "refs/pull/125/merge",
                "sha": "abc123def456",
            },
        },
        engine_version="2.0.0",
        timestamp="2026-04-30T00:00:00Z",
    )


def _record(decision_id, tenant, attestation):
    return record_release_attestation(
        decision_id=decision_id,
        tenant_id=tenant,
        repo="org/service-api",
        pr_number=125,
        attestation=attestation,
    )


def _attestation_rows(tenant_id, decision_id):
    """All audit_attestations rows for a given decision, ordered by created_at."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT attestation_id, signed_payload_hash, created_at
            FROM audit_attestations
            WHERE tenant_id = ? AND decision_id = ?
            ORDER BY created_at ASC, attestation_id ASC
            """,
            (tenant_id, decision_id),
        )
        return cur.fetchall()
    finally:
        conn.close()


# ── Headline contract: re-runs of the same PR ───────────────────────────────
class TestRerunsOfSamePR:
    """The empirical case from the PR #125 demo: two CI runs against the
    same PR.  decision_id stays the same; attestation_id must NOT.
    """

    def test_same_pr_two_runs_yield_same_decision_id_different_attestation_ids(
        self, clean_db
    ):
        # Same PR → same code → same policy → same metrics.  Only the
        # workflow_run.run_id differs (the only thing that legitimately
        # varies between two CI invocations of an identical PR).
        bundle_run1 = _build_for_run(run_id="ci-run-aaaa")
        bundle_run2 = _build_for_run(run_id="ci-run-bbbb")

        # decision_id IS deterministic post-#128.
        assert bundle_run1.decision_id == bundle_run2.decision_id

        # signed_payload_hash differs: workflow_run.run_id is in
        # bundle.signals which the canonicalized payload hashes over.
        att_run1 = build_attestation_from_bundle(bundle_run1)
        att_run2 = build_attestation_from_bundle(bundle_run2)
        h1 = att_run1["signature"]["signed_payload_hash"]
        h2 = att_run2["signature"]["signed_payload_hash"]
        assert h1 != h2, "DSSE payload hashes must differ across runs"

        # And so must attestation_id (= signed_payload_hash).
        id1 = _record(bundle_run1.decision_id, "tenant-test", att_run1)
        id2 = _record(bundle_run2.decision_id, "tenant-test", att_run2)
        assert id1 != id2, "attestation_id must be per-run unique"

        # Both rows are persisted — no overwrite of the first run.
        rows = _attestation_rows("tenant-test", bundle_run1.decision_id)
        assert len(rows) == 2
        attestation_ids = {row[0] for row in rows}
        assert attestation_ids == {id1, id2}

    def test_signed_payload_hashes_persist_alongside_attestation_ids(self, clean_db):
        """Each row stores its own signed_payload_hash, so the audit
        table reflects the actual cryptographic envelope of every run."""
        bundle = _build_for_run(run_id="ci-run-1111")
        att1 = build_attestation_from_bundle(bundle)
        bundle2 = _build_for_run(run_id="ci-run-2222")
        att2 = build_attestation_from_bundle(bundle2)

        _record(bundle.decision_id, "tenant-test", att1)
        _record(bundle2.decision_id, "tenant-test", att2)

        rows = _attestation_rows("tenant-test", bundle.decision_id)
        signed_hashes_in_db = {row[1] for row in rows}
        # Each row carries its run's own signed_payload_hash, prefixed
        # `sha256:` per the storage convention.
        h1 = att1["signature"]["signed_payload_hash"]
        h2 = att2["signature"]["signed_payload_hash"]
        norm = lambda v: v if v.startswith("sha256:") else f"sha256:{v}"
        assert signed_hashes_in_db == {norm(h1), norm(h2)}


# ── Idempotency: same signed envelope recorded twice = one row ─────────────
class TestIdempotencyForSameSignedEnvelope:
    """Calling record_release_attestation twice with the same DSSE
    artifact (same signed_payload_hash) MUST be a no-op for the second
    call.  This guards against a worker/retry double-record producing
    duplicate audit log rows.
    """

    def test_same_attestation_object_recorded_twice_yields_one_row(self, clean_db):
        bundle = _build_for_run(run_id="ci-run-1111")
        att = build_attestation_from_bundle(bundle)

        id_first = _record(bundle.decision_id, "tenant-test", att)
        id_second = _record(bundle.decision_id, "tenant-test", att)

        assert id_first == id_second, (
            "same signed_payload_hash → same attestation_id"
        )
        rows = _attestation_rows("tenant-test", bundle.decision_id)
        assert len(rows) == 1, (
            "PRIMARY KEY (tenant_id, attestation_id) collapses the duplicate"
        )


# ── Mixed workload: idempotency AND per-run uniqueness on the same decision ─
class TestMixedRecording:
    """Verify the boundary explicitly: two distinct DSSE envelopes for the
    same decision_id produce two rows; recording either of them again is
    a no-op.
    """

    def test_two_runs_then_replay_first_run_does_not_grow_rows(self, clean_db):
        # Two CI runs (different signed payloads, same decision_id).
        bundle1 = _build_for_run(run_id="ci-run-1111")
        bundle2 = _build_for_run(run_id="ci-run-2222")
        att1 = build_attestation_from_bundle(bundle1)
        att2 = build_attestation_from_bundle(bundle2)

        id1 = _record(bundle1.decision_id, "tenant-test", att1)
        id2 = _record(bundle2.decision_id, "tenant-test", att2)
        assert id1 != id2

        # Replay run 1 verbatim — must NOT create a third row.
        id1_replay = _record(bundle1.decision_id, "tenant-test", att1)
        assert id1_replay == id1

        rows = _attestation_rows("tenant-test", bundle1.decision_id)
        assert len(rows) == 2  # still just run1 + run2


# ── Schema state: the legacy unique index is gone ───────────────────────────
class TestSchemaState:
    """The (tenant_id, decision_id) UNIQUE index that caused the collapse
    must be absent after init_db() (migration 20260430_044 dropped it).
    Existing PRIMARY KEY (tenant_id, attestation_id) stays.
    """

    def test_legacy_unique_index_is_dropped(self, clean_db):
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA index_list(audit_attestations)")
            indexes = {row[1] for row in cur.fetchall()}
            assert "uq_audit_attestations_tenant_decision" not in indexes, (
                "the (tenant_id, decision_id) UNIQUE index must be dropped "
                "for per-run attestation_ids"
            )
        finally:
            conn.close()

    def test_primary_key_still_tenant_attestation(self, clean_db):
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(audit_attestations)")
            info = cur.fetchall()
            pk = [row[1] for row in sorted((r for r in info if r[5] > 0), key=lambda r: r[5])]
            assert pk == ["tenant_id", "attestation_id"]
        finally:
            conn.close()

    def test_migration_044_is_applied(self, clean_db):
        """The forward-only migration registry must show the drop landed."""
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT 1 FROM schema_migrations "
                "WHERE migration_id = '20260430_044_attestation_id_per_run_unique'"
            )
            assert cur.fetchone() is not None
        finally:
            conn.close()
