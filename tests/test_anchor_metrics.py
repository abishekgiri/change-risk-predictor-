from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from releasegate.anchoring.anchor_scheduler import tick
from releasegate.anchoring.metrics import get_anchor_health
from releasegate.anchoring.models import mark_anchor_job_failed, upsert_anchor_job
from releasegate.attestation.service import (
    build_attestation_from_bundle,
    build_bundle_from_analysis_result,
)
from releasegate.audit.attestations import record_release_attestation
from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)


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


def test_anchor_health_flags_no_anchor_and_failure_streak(clean_db, monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_HEALTH_FAILURE_STREAK", "3")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_HEALTH_DRIFT_THRESHOLD", "1")
    _record_attestation(
        tenant_id="tenant-health",
        repo="org/repo",
        pr_number=301,
        commit_sha="ccc333",
        timestamp="2026-03-03T08:00:00Z",
    )

    now = datetime.now(timezone.utc)
    for idx in range(3):
        job = upsert_anchor_job(
            tenant_id="tenant-health",
            root_hash=f"failed-root-{idx}",
            date_utc="2026-03-03",
            ledger_head_seq=idx + 1,
            next_attempt_at=now.isoformat(),
        )
        mark_anchor_job_failed(
            tenant_id="tenant-health",
            job_id=str(job["job_id"]),
            attempts=idx + 1,
            next_attempt_at=(now + timedelta(minutes=5)).isoformat(),
            last_error="simulated failure",
        )

    health = get_anchor_health(tenant_id="tenant-health")
    assert health["is_healthy"] is False
    assert "NO_CONFIRMED_ANCHOR" in health["reasons"]
    assert "CONSECUTIVE_FAILURES" in health["reasons"]
    assert health["consecutive_failures"] >= 3


def test_anchor_metrics_endpoint_returns_anchor_health(clean_db, monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "local_transparency")
    _record_attestation(
        tenant_id="tenant-api",
        repo="org/repo",
        pr_number=302,
        commit_sha="ddd444",
        timestamp="2026-03-03T10:00:00Z",
    )
    tick(tenant_id="tenant-api")

    response = client.get(
        "/internal/metrics/anchor",
        params={"tenant_id": "tenant-api"},
        headers=jwt_headers(
            tenant_id="tenant-api",
            roles=["auditor"],
            scopes=["checkpoint:read"],
        ),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["tenant_id"] == "tenant-api"
    assert isinstance(body["anchor"]["is_healthy"], bool)
    assert "last_anchor_hash" in body["anchor"]
