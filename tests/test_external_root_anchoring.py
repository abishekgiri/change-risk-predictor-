from __future__ import annotations

import os
import sqlite3
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from releasegate.anchoring.roots import anchor_transparency_root
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
        risk_score=0.9,
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


def test_external_root_anchor_is_recorded_idempotently(clean_db, monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "local_transparency")
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=101,
        commit_sha="abc123",
        timestamp="2026-02-27T10:00:00Z",
    )

    first = anchor_transparency_root(
        date_utc="2026-02-27",
        tenant_id="tenant-a",
        provider_name="local_transparency",
    )
    second = anchor_transparency_root(
        date_utc="2026-02-27",
        tenant_id="tenant-a",
        provider_name="local_transparency",
    )
    assert first is not None
    assert second is not None
    assert first["anchor_id"] == second["anchor_id"]
    assert first["provider"] == "local_transparency"

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COUNT(*)
            FROM audit_external_root_anchors
            WHERE tenant_id = ? AND provider = ? AND date_utc = ? AND root_hash = ?
            """,
            ("tenant-a", "local_transparency", "2026-02-27", first["root_hash"]),
        )
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()


def test_http_anchor_provider_records_external_receipt(clean_db, monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "http_transparency")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_HTTP_URL", "https://anchor.example/api/anchors")
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=102,
        commit_sha="def456",
        timestamp="2026-02-28T10:00:00Z",
    )

    class _Response:
        status_code = 201
        text = '{"log_index": "42", "root_hash": "placeholder"}'

        def __init__(self, body: Dict[str, Any]):
            self._body = body

        def json(self):
            return self._body

    def _fake_post(url: str, json: Dict[str, Any], headers: Dict[str, Any], timeout: float):
        assert url == "https://anchor.example/api/anchors"
        return _Response({"log_index": "42", "root_hash": json["root_hash"]})

    import releasegate.anchoring.provider as provider_mod

    monkeypatch.setattr(provider_mod.requests, "post", _fake_post)
    anchored = anchor_transparency_root(
        date_utc="2026-02-28",
        tenant_id="tenant-a",
        provider_name="http_transparency",
    )
    assert anchored is not None
    assert anchored["provider"] == "http_transparency"
    assert anchored["external_ref"] == "42"


def test_transparency_root_anchor_endpoints(clean_db, monkeypatch):
    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "local_transparency")
    _record_attestation(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=103,
        commit_sha="ghi789",
        timestamp="2026-02-26T10:00:00Z",
    )

    anchor_resp = client.post(
        "/transparency/root/2026-02-26/anchor",
        params={"tenant_id": "tenant-a"},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["admin"],
            scopes=["proofpack:read"],
        ),
    )
    assert anchor_resp.status_code == 200
    body = anchor_resp.json()
    assert body["ok"] is True
    assert body["anchor"]["provider"] == "local_transparency"

    list_resp = client.get(
        "/transparency/root/2026-02-26/anchors",
        params={"tenant_id": "tenant-a"},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["auditor"],
            scopes=["proofpack:read"],
        ),
    )
    assert list_resp.status_code == 200
    listing = list_resp.json()
    assert listing["ok"] is True
    assert listing["count"] >= 1
    assert listing["items"][0]["date_utc"] == "2026-02-26"
