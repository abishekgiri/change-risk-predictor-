from __future__ import annotations

import os

from fastapi.testclient import TestClient

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
        decision="ALLOW",
        reason_codes=["POLICY_ALLOWED"],
        signals={"changed_files": 7},
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


def test_publish_get_verify_independent_daily_checkpoint(monkeypatch):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()

    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "local_transparency")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "phase14-secret")

    _record_attestation(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=301,
        commit_sha="abc123",
        timestamp="2026-03-02T12:00:00Z",
    )

    publish = client.post(
        "/anchors/checkpoints/daily/2026-03-02/publish",
        json={"tenant_id": "tenant-a", "publish_anchor": True},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["admin"],
            scopes=["checkpoint:read", "proofpack:read"],
        ),
    )
    assert publish.status_code == 200, publish.text
    published = publish.json()
    assert published["schema_name"] == "independent_daily_checkpoint"
    assert published["created"] is True
    assert (published.get("payload") or {}).get("ledger_root")
    assert ((published.get("external_anchor") or {}).get("provider")) == "local_transparency"
    checkpoint_id = (published.get("ids") or {}).get("checkpoint_id")
    assert checkpoint_id

    replay = client.post(
        "/anchors/checkpoints/daily/2026-03-02/publish",
        json={"tenant_id": "tenant-a", "publish_anchor": True},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["admin"],
            scopes=["checkpoint:read", "proofpack:read"],
        ),
    )
    assert replay.status_code == 200, replay.text
    replayed = replay.json()
    assert replayed["created"] is False
    assert ((replayed.get("ids") or {}).get("checkpoint_id")) == checkpoint_id

    fetched = client.get(
        "/anchors/checkpoints/daily/2026-03-02",
        params={"tenant_id": "tenant-a"},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["auditor"],
            scopes=["checkpoint:read", "proofpack:read"],
        ),
    )
    assert fetched.status_code == 200, fetched.text
    fetched_payload = fetched.json()
    assert ((fetched_payload.get("ids") or {}).get("checkpoint_id")) == checkpoint_id

    verify = client.get(
        "/anchors/checkpoints/daily/2026-03-02/verify",
        params={"tenant_id": "tenant-a"},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["auditor"],
            scopes=["checkpoint:read", "proofpack:read"],
        ),
    )
    assert verify.status_code == 200, verify.text
    report = verify.json()
    assert report["exists"] is True
    assert report["valid"] is True
    assert report["signature_valid"] is True
    assert report["anchor_present"] is True
