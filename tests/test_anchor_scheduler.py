from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from releasegate.anchoring.anchor_scheduler import tick
from releasegate.anchoring.anchor_service import ensure_due_anchor_job, process_retryable_anchor_jobs
from releasegate.attestation.service import (
    build_attestation_from_bundle,
    build_bundle_from_analysis_result,
)
from releasegate.audit.attestations import record_release_attestation
from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def _record_attestation(
    *,
    tenant_id: str,
    repo: str,
    pr_number: int,
    commit_sha: str,
    timestamp: str,
) -> None:
    bundle = build_bundle_from_analysis_result(
        tenant_id=tenant_id,
        repo=repo,
        pr_number=pr_number,
        commit_sha=commit_sha,
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.8,
        decision="BLOCK",
        reason_codes=["POLICY_BLOCKED"],
        signals={"changed_files": 12},
        engine_version="2.0.0",
        timestamp=timestamp,
    )
    attestation = build_attestation_from_bundle(bundle)
    record_release_attestation(
        decision_id=bundle.decision_id,
        tenant_id=tenant_id,
        repo=repo,
        pr_number=pr_number,
        attestation=attestation,
    )


def _row_count(query: str, params: tuple[Any, ...]) -> int:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        row = cur.fetchone()
        return int(row[0] if row else 0)
    finally:
        conn.close()


def test_anchor_tick_runs_idempotently_for_same_root(clean_db, monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "local_transparency")
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=201,
        commit_sha="aaa111",
        timestamp="2026-03-02T12:00:00Z",
    )

    first = tick(tenant_id="tenant-a")
    second = tick(tenant_id="tenant-a")
    assert first["ok"] is True
    assert second["ok"] is True

    anchor_count = _row_count(
        "SELECT COUNT(*) FROM audit_external_root_anchors WHERE tenant_id = ?",
        ("tenant-a",),
    )
    job_count = _row_count(
        "SELECT COUNT(*) FROM anchor_jobs WHERE tenant_id = ?",
        ("tenant-a",),
    )
    confirmed_count = _row_count(
        "SELECT COUNT(*) FROM anchor_jobs WHERE tenant_id = ? AND status = 'CONFIRMED'",
        ("tenant-a",),
    )
    assert anchor_count == 1
    assert job_count == 1
    assert confirmed_count == 1


def test_anchor_retry_records_failure_and_next_attempt(clean_db, monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "local_transparency")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_MAX_ATTEMPTS", "5")
    _record_attestation(
        tenant_id="tenant-b",
        repo="org/repo",
        pr_number=202,
        commit_sha="bbb222",
        timestamp="2026-03-02T12:30:00Z",
    )

    ensured = ensure_due_anchor_job(tenant_id="tenant-b")
    assert ensured["job"] is not None

    import releasegate.anchoring.anchor_service as anchor_service

    def _raise(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        raise RuntimeError("anchor submission failed")

    monkeypatch.setattr(anchor_service, "anchor_transparency_root", _raise)
    report = process_retryable_anchor_jobs(tenant_id="tenant-b", limit=10)
    assert report["processed"] == 1
    result = report["results"][0]
    assert result["ok"] is False

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT status, attempts, next_attempt_at, last_error, created_at
            FROM anchor_jobs
            WHERE tenant_id = ?
            LIMIT 1
            """,
            ("tenant-b",),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    assert row is not None
    status, attempts, next_attempt_at, last_error, created_at = row
    assert status == "FAILED"
    assert int(attempts) == 1
    assert "anchor submission failed" in str(last_error)

    next_dt = datetime.fromisoformat(str(next_attempt_at).replace("Z", "+00:00")).astimezone(timezone.utc)
    created_dt = datetime.fromisoformat(str(created_at).replace("Z", "+00:00")).astimezone(timezone.utc)
    assert next_dt >= created_dt
