from __future__ import annotations

import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from releasegate.attestation.service import (
    build_attestation_from_bundle,
    build_bundle_from_analysis_result,
)
from releasegate.audit.attestations import record_release_attestation
from releasegate.audit.transparency import get_transparency_entry, list_transparency_latest
from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db

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
    decision_suffix: str,
) -> tuple[str, str]:
    bundle = build_bundle_from_analysis_result(
        tenant_id=tenant_id,
        repo=repo,
        pr_number=pr_number,
        commit_sha=commit_sha,
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.9,
        decision="BLOCK",
        reason_codes=[f"POLICY_BLOCKED_{decision_suffix}"],
        signals={"changed_files": 42},
        engine_version="2.0.0",
        timestamp=timestamp,
    )
    attestation = build_attestation_from_bundle(bundle)
    attestation_id = record_release_attestation(
        decision_id=bundle.decision_id,
        tenant_id=tenant_id,
        repo=repo,
        pr_number=pr_number,
        attestation=attestation,
    )
    return attestation_id, bundle.decision_id


def test_transparency_entry_created_on_attestation_record(clean_db, monkeypatch):
    monkeypatch.setenv("RELEASEGATE_GIT_SHA", "abcde12345")
    attestation_id, _ = _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=15,
        commit_sha="abc123",
        timestamp="2026-02-10T23:21:00Z",
        decision_suffix="A",
    )

    listing = list_transparency_latest(limit=10, tenant_id="tenant-a")
    assert listing["ok"] is True
    assert listing["items"]
    entry = listing["items"][0]
    assert entry["attestation_id"] == attestation_id
    assert entry["payload_hash"].startswith("sha256:")
    assert entry["subject"]["repo"] == "org/service-api"
    assert entry["subject"]["commit_sha"] == "abc123"
    assert entry["subject"]["pr_number"] == 15
    assert entry["engine_build"]["git_sha"] == "abcde12345"
    assert entry["engine_build"]["version"] == "2.0.0"


def test_transparency_log_is_immutable(clean_db):
    attestation_id, _ = _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=16,
        commit_sha="def456",
        timestamp="2026-02-11T10:00:00Z",
        decision_suffix="B",
    )

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        with pytest.raises(sqlite3.DatabaseError):
            cur.execute(
                "UPDATE audit_transparency_log SET repo = ? WHERE attestation_id = ?",
                ("org/other", attestation_id),
            )
        with pytest.raises(sqlite3.DatabaseError):
            cur.execute(
                "DELETE FROM audit_transparency_log WHERE attestation_id = ?",
                (attestation_id,),
            )
    finally:
        conn.close()


def test_transparency_insert_is_idempotent(clean_db):
    tenant_id = "tenant-a"
    repo = "org/service-api"
    pr_number = 17
    commit_sha = "ghi789"
    timestamp = "2026-02-11T11:00:00Z"

    bundle = build_bundle_from_analysis_result(
        tenant_id=tenant_id,
        repo=repo,
        pr_number=pr_number,
        commit_sha=commit_sha,
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.7,
        decision="BLOCK",
        reason_codes=["POLICY_BLOCKED"],
        signals={"changed_files": 22},
        engine_version="2.0.0",
        timestamp=timestamp,
    )
    attestation = build_attestation_from_bundle(bundle)

    attestation_id_first = record_release_attestation(
        decision_id=bundle.decision_id,
        tenant_id=tenant_id,
        repo=repo,
        pr_number=pr_number,
        attestation=attestation,
    )
    attestation_id_second = record_release_attestation(
        decision_id=bundle.decision_id,
        tenant_id=tenant_id,
        repo=repo,
        pr_number=pr_number,
        attestation=attestation,
    )

    assert attestation_id_first == attestation_id_second

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM audit_transparency_log WHERE tenant_id = ? AND attestation_id = ?",
            (tenant_id, attestation_id_first),
        )
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()


def test_transparency_latest_orders_newest_first(clean_db):
    first_id, _ = _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=18,
        commit_sha="jkl012",
        timestamp="2026-02-10T10:00:00Z",
        decision_suffix="C",
    )
    second_id, _ = _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=19,
        commit_sha="mno345",
        timestamp="2026-02-11T10:00:00Z",
        decision_suffix="D",
    )

    listing = list_transparency_latest(limit=2, tenant_id="tenant-a")
    ids = [item["attestation_id"] for item in listing["items"]]
    assert ids == [second_id, first_id]


def test_transparency_get_by_id_and_404(clean_db):
    attestation_id, _ = _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=20,
        commit_sha="pqr678",
        timestamp="2026-02-11T12:00:00Z",
        decision_suffix="E",
    )

    direct = get_transparency_entry(attestation_id=attestation_id, tenant_id="tenant-a")
    assert direct is not None
    assert direct["attestation_id"] == attestation_id

    latest_resp = client.get("/transparency/latest", params={"limit": 5, "tenant_id": "tenant-a"})
    assert latest_resp.status_code == 200
    latest_body = latest_resp.json()
    assert latest_body["ok"] is True
    assert any(item["attestation_id"] == attestation_id for item in latest_body["items"])

    by_id_resp = client.get(f"/transparency/{attestation_id}", params={"tenant_id": "tenant-a"})
    assert by_id_resp.status_code == 200
    by_id_body = by_id_resp.json()
    assert by_id_body["ok"] is True
    assert by_id_body["item"]["attestation_id"] == attestation_id

    not_found_resp = client.get("/transparency/not-found", params={"tenant_id": "tenant-a"})
    assert not_found_resp.status_code == 404


def test_transparency_latest_limit_validation(clean_db):
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=21,
        commit_sha="stu901",
        timestamp="2026-02-11T13:00:00Z",
        decision_suffix="F",
    )

    default_resp = client.get("/transparency/latest", params={"tenant_id": "tenant-a"})
    assert default_resp.status_code == 200
    default_body = default_resp.json()
    assert default_body["limit"] == 50

    bad_resp = client.get("/transparency/latest", params={"tenant_id": "tenant-a", "limit": -1})
    assert bad_resp.status_code == 400
    assert "limit must be greater than 0" in str(bad_resp.json().get("detail", ""))

    clamped_resp = client.get("/transparency/latest", params={"tenant_id": "tenant-a", "limit": 9999})
    assert clamped_resp.status_code == 200
    clamped_body = clamped_resp.json()
    assert clamped_body["limit"] == 500


def test_transparency_engine_git_sha_null_when_env_unset(clean_db, monkeypatch):
    monkeypatch.delenv("RELEASEGATE_GIT_SHA", raising=False)
    monkeypatch.delenv("RELEASEGATE_ENGINE_GIT_SHA", raising=False)
    monkeypatch.delenv("RELEASEGATE_VERSION", raising=False)
    attestation_id, _ = _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=22,
        commit_sha="vwx234",
        timestamp="2026-02-11T14:00:00Z",
        decision_suffix="G",
    )
    entry = get_transparency_entry(attestation_id=attestation_id, tenant_id="tenant-a")
    assert entry is not None
    assert entry["engine_build"]["git_sha"] is None
    assert entry["engine_build"]["version"] == "2.0.0"
