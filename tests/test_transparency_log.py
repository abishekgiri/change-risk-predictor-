from __future__ import annotations

import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from releasegate.attestation.merkle import LEAF_VERSION, TREE_RULE
from releasegate.attestation.sdk import verify_inclusion_proof
from releasegate.attestation.service import (
    build_attestation_from_bundle,
    build_bundle_from_analysis_result,
)
from releasegate.audit.attestations import record_release_attestation
from releasegate.audit.transparency import (
    get_or_compute_transparency_root,
    get_transparency_entry,
    list_transparency_latest,
)
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


def test_transparency_daily_root_deterministic(clean_db):
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=23,
        commit_sha="aaa111",
        timestamp="2026-02-12T08:00:00Z",
        decision_suffix="H1",
    )
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=24,
        commit_sha="bbb222",
        timestamp="2026-02-12T09:00:00Z",
        decision_suffix="H2",
    )
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=25,
        commit_sha="ccc333",
        timestamp="2026-02-12T10:00:00Z",
        decision_suffix="H3",
    )

    root_first = get_or_compute_transparency_root(date_utc="2026-02-12", tenant_id="tenant-a")
    root_second = get_or_compute_transparency_root(date_utc="2026-02-12", tenant_id="tenant-a")

    assert root_first is not None
    assert root_second is not None
    assert root_first["root_hash"] == root_second["root_hash"]
    assert root_first["leaf_count"] == 3
    assert root_second["leaf_count"] == 3


def test_transparency_proof_verification_and_tamper_failure(clean_db):
    target_attestation_id, _ = _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=26,
        commit_sha="ddd444",
        timestamp="2026-02-13T08:00:00Z",
        decision_suffix="I1",
    )
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=27,
        commit_sha="eee555",
        timestamp="2026-02-13T09:00:00Z",
        decision_suffix="I2",
    )
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=28,
        commit_sha="fff666",
        timestamp="2026-02-13T10:00:00Z",
        decision_suffix="I3",
    )

    proof_resp = client.get(f"/transparency/proof/{target_attestation_id}", params={"tenant_id": "tenant-a"})
    assert proof_resp.status_code == 200
    proof_payload = proof_resp.json()
    assert proof_payload["ok"] is True
    assert proof_payload["leaf_version"] == LEAF_VERSION
    assert proof_payload["tree_rule"] == TREE_RULE
    assert verify_inclusion_proof(proof_payload) is True

    tampered = dict(proof_payload)
    tampered_steps = [dict(step) for step in proof_payload.get("proof") or []]
    if tampered_steps:
        tampered_steps[0]["hash"] = "sha256:" + ("0" * 64)
        tampered["proof"] = tampered_steps
    else:
        tampered["leaf_hash"] = "sha256:" + ("0" * 64)
    assert verify_inclusion_proof(tampered) is False


def test_transparency_odd_leaf_count_duplicate_rule(clean_db):
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=29,
        commit_sha="ggg777",
        timestamp="2026-02-14T08:00:00Z",
        decision_suffix="J1",
    )
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=30,
        commit_sha="hhh888",
        timestamp="2026-02-14T09:00:00Z",
        decision_suffix="J2",
    )
    last_id, _ = _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=31,
        commit_sha="iii999",
        timestamp="2026-02-14T10:00:00Z",
        decision_suffix="J3",
    )

    proof_resp = client.get(f"/transparency/proof/{last_id}", params={"tenant_id": "tenant-a"})
    assert proof_resp.status_code == 200
    proof_payload = proof_resp.json()
    assert proof_payload["tree_rule"] == TREE_RULE
    # 3 leaves -> duplicate-last rule produces 2 proof nodes.
    assert len(proof_payload["proof"]) == 2
    assert verify_inclusion_proof(proof_payload) is True


def test_transparency_roots_table_is_immutable(clean_db):
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/service-api",
        pr_number=32,
        commit_sha="jjj000",
        timestamp="2026-02-15T10:00:00Z",
        decision_suffix="K1",
    )
    root_resp = client.get("/transparency/root/2026-02-15", params={"tenant_id": "tenant-a"})
    assert root_resp.status_code == 200
    root_hash = root_resp.json()["root_hash"]

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        with pytest.raises(sqlite3.DatabaseError):
            cur.execute(
                "UPDATE audit_transparency_roots SET root_hash = ? WHERE tenant_id = ? AND date_utc = ?",
                ("sha256:" + ("f" * 64), "tenant-a", "2026-02-15"),
            )
        with pytest.raises(sqlite3.DatabaseError):
            cur.execute(
                "DELETE FROM audit_transparency_roots WHERE tenant_id = ? AND date_utc = ?",
                ("tenant-a", "2026-02-15"),
            )
    finally:
        conn.close()

    root_resp_again = client.get("/transparency/root/2026-02-15", params={"tenant_id": "tenant-a"})
    assert root_resp_again.status_code == 200
    assert root_resp_again.json()["root_hash"] == root_hash
