from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from releasegate.anchoring.independent_checkpoints import (
    create_independent_daily_checkpoint,
    verify_independent_daily_checkpoint,
)
from releasegate.attestation.service import (
    build_attestation_from_bundle,
    build_bundle_from_analysis_result,
)
from releasegate.audit.anchor_scheduler import (
    write_git_anchor_artifact,
    write_immutable_anchor_artifact,
)
from releasegate.audit.attestations import record_release_attestation
from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db
from tests.auth_helpers import jwt_headers


client = TestClient(app)
TENANT_ID = "tenant-phase28-anchor"
CHECKPOINT_SIGNING_KEY = "phase28-checkpoint-signing-key"


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    os.environ["RELEASEGATE_CHECKPOINT_SIGNING_KEY"] = CHECKPOINT_SIGNING_KEY
    yield
    os.environ.pop("RELEASEGATE_CHECKPOINT_SIGNING_KEY", None)
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
        policy_hash="phase28-policy",
        policy_version="1.0.0",
        policy_bundle_hash="phase28-bundle",
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


def _seed_checkpoint(tenant_id: str, date_utc: str, publish_anchor: bool = True) -> dict:
    _record_attestation(
        tenant_id=tenant_id,
        repo="org/phase28",
        pr_number=401,
        commit_sha="abc123",
        timestamp=f"{date_utc}T10:00:00Z",
    )
    return create_independent_daily_checkpoint(
        tenant_id=tenant_id,
        date_utc=date_utc,
        publish_anchor=publish_anchor,
    )


def test_checkpoint_artifact_signature_valid(clean_db):
    checkpoint = _seed_checkpoint(TENANT_ID, "2026-03-01", publish_anchor=False)
    verification = verify_independent_daily_checkpoint(
        date_utc="2026-03-01",
        tenant_id=TENANT_ID,
        require_anchor=False,
    )
    assert checkpoint["payload"]["checkpoint_id"]
    assert verification["exists"] is True
    assert verification["signature_valid"] is True
    assert verification["valid"] is True


def test_anchor_writer_s3_mocked(clean_db, tmp_path: Path, monkeypatch):
    checkpoint = _seed_checkpoint(TENANT_ID, "2026-03-02", publish_anchor=False)
    immutable_dir = tmp_path / "object_lock"
    monkeypatch.setenv("RELEASEGATE_EXTERNAL_ANCHOR_IMMUTABLE_DIR", str(immutable_dir))
    write_result = write_immutable_anchor_artifact(
        tenant_id=TENANT_ID,
        date_utc="2026-03-02",
        checkpoint=checkpoint,
    )
    path = Path(write_result["path"])
    assert path.exists()
    assert path.read_text(encoding="utf-8")


def test_anchor_writer_git_mocked(clean_db, tmp_path: Path, monkeypatch):
    checkpoint = _seed_checkpoint(TENANT_ID, "2026-03-03", publish_anchor=False)
    git_dir = tmp_path / "git_mirror"
    monkeypatch.setenv("RELEASEGATE_EXTERNAL_ANCHOR_GIT_MIRROR_DIR", str(git_dir))
    write_result = write_git_anchor_artifact(
        tenant_id=TENANT_ID,
        date_utc="2026-03-03",
        checkpoint=checkpoint,
    )
    path = Path(write_result["path"])
    assert path.exists()
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    assert checkpoint["payload"]["checkpoint_id"] in lines[-1]


def test_proof_bundle_verifies_chain(clean_db):
    checkpoint = _seed_checkpoint(TENANT_ID, "2026-03-04", publish_anchor=True)
    checkpoint_id = checkpoint["payload"]["checkpoint_id"]
    response = client.get(
        f"/audit/checkpoints/{checkpoint_id}/proof",
        params={"tenant_id": TENANT_ID},
        headers=jwt_headers(tenant_id=TENANT_ID, scopes=["checkpoint:read", "proofpack:read"]),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["checkpoint_id"] == checkpoint_id
    assert payload["chain_segment"]["checkpoint_hash"]
    assert payload["verification"]["valid"] is True
