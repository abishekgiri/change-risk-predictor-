from __future__ import annotations

import os
import sqlite3

from fastapi.testclient import TestClient
import pytest

from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_analysis_result
from releasegate.audit.attestations import record_release_attestation
from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def _record(tenant: str, repo: str, pr: int, ts: str) -> str:
    bundle = build_bundle_from_analysis_result(
        tenant_id=tenant,
        repo=repo,
        pr_number=pr,
        commit_sha="a" * 40,
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="bundle-hash",
        risk_score=0.5,
        decision="BLOCK",
        reason_codes=["POLICY_BLOCKED"],
        signals={"dependency_provenance": {}},
        engine_version="2.0.0",
        timestamp=ts,
    )
    attestation = build_attestation_from_bundle(bundle)
    return record_release_attestation(
        decision_id=bundle.decision_id,
        tenant_id=tenant,
        repo=repo,
        pr_number=pr,
        attestation=attestation,
    )


def test_get_attestation_by_id_and_listing_filters():
    _reset_db()

    att1 = _record("tenant-a", "org/repo-a", 1, "2026-02-13T10:00:00Z")
    _record("tenant-a", "org/repo-b", 2, "2026-02-13T11:00:00Z")

    by_id = client.get(f"/attestations/{att1}", params={"tenant_id": "tenant-a"})
    assert by_id.status_code == 200
    payload = by_id.json()
    assert payload["ok"] is True
    assert payload["item"]["attestation_id"] == att1

    listing = client.get(
        "/attestations",
        params={
            "tenant_id": "tenant-a",
            "repo": "org/repo-b",
            "since": "2026-02-13T10:30:00Z",
            "limit": 10,
        },
    )
    assert listing.status_code == 200
    body = listing.json()
    assert body["ok"] is True
    assert body["count"] == 1
    assert body["items"][0]["repo"] == "org/repo-b"


def test_get_attestation_404():
    _reset_db()
    resp = client.get("/attestations/not-found", params={"tenant_id": "tenant-a"})
    assert resp.status_code == 404


def test_attestation_log_is_append_only():
    _reset_db()
    attestation_id = _record("tenant-a", "org/repo-a", 1, "2026-02-13T10:00:00Z")

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        with pytest.raises(sqlite3.DatabaseError):
            cur.execute(
                "UPDATE audit_attestations SET repo = ? WHERE attestation_id = ?",
                ("org/changed", attestation_id),
            )
        with pytest.raises(sqlite3.DatabaseError):
            cur.execute(
                "DELETE FROM audit_attestations WHERE attestation_id = ?",
                (attestation_id,),
            )
    finally:
        conn.close()
