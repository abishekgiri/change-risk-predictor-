from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


def _response(status_code: int, body: dict):
    class _Response:
        def __init__(self, code: int, payload: dict):
            self.status_code = code
            self._payload = payload

        def json(self):
            return self._payload

        @property
        def text(self):
            return json.dumps(self._payload, sort_keys=True)

    return _Response(status_code, body)


def _set_ed25519_env(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    monkeypatch.setenv("RELEASEGATE_ATTESTATION_KEY_ID", "anchor-ed25519-key")
    monkeypatch.setenv("RELEASEGATE_SIGNING_KEY", base64.b64encode(private_raw).decode("ascii"))
    monkeypatch.setenv(
        "RELEASEGATE_ATTESTATION_PUBLIC_KEYS",
        json.dumps({"anchor-ed25519-key": public_pem}, separators=(",", ":"), sort_keys=True),
    )


def test_publish_strict_mode_rejects_local_provider(monkeypatch):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()

    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "local_transparency")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_STRICT", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_SIG_ALG", "ed25519")
    _set_ed25519_env(monkeypatch)

    _record_attestation(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=302,
        commit_sha="def456",
        timestamp="2026-03-03T09:00:00Z",
    )

    publish = client.post(
        "/anchors/checkpoints/daily/2026-03-03/publish",
        json={"tenant_id": "tenant-a", "publish_anchor": True},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["admin"],
            scopes=["checkpoint:read", "proofpack:read"],
        ),
    )
    assert publish.status_code == 400
    assert "INDEPENDENCE_REQUIRED" in publish.text


def test_verify_independent_daily_checkpoint_fails_when_external_payload_mismatches(monkeypatch):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()

    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "http_transparency")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_STRICT", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_SIG_ALG", "ed25519")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_HTTP_URL", "https://anchor.example/api/root")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_HTTP_CHECKPOINT_PUBLISH_URL", "https://anchor.example/api/checkpoints")
    _set_ed25519_env(monkeypatch)

    _record_attestation(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=303,
        commit_sha="ghi789",
        timestamp="2026-03-04T09:00:00Z",
    )

    import releasegate.anchoring.provider as provider_mod
    import releasegate.anchoring.independent_checkpoints as cp_mod

    def _fake_post(url: str, json: dict, headers: dict, timeout: float):
        if "api/root" in url:
            return _response(201, {"log_index": "42", "root_hash": json["root_hash"]})
        if "api/checkpoints" in url:
            return _response(201, {"external_ref": "cp-42", "fetch_url": "https://anchor.example/checkpoints/{external_ref}"})
        raise AssertionError(f"unexpected post url {url}")

    def _fake_get(url: str, headers: dict, timeout: float, params=None):
        return _response(
            200,
            {
                "checkpoint": {
                    "payload": {
                        "ledger_root": "sha256:tampered-root",
                        "ledger_size": 0,
                    },
                    "integrity": {"checkpoint_hash": "sha256:tampered-hash"},
                }
            },
        )

    monkeypatch.setattr(provider_mod.requests, "post", _fake_post)
    monkeypatch.setattr(cp_mod.requests, "post", _fake_post)
    monkeypatch.setattr(cp_mod.requests, "get", _fake_get)

    publish = client.post(
        "/anchors/checkpoints/daily/2026-03-04/publish",
        json={"tenant_id": "tenant-a", "publish_anchor": True},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["admin"],
            scopes=["checkpoint:read", "proofpack:read"],
        ),
    )
    assert publish.status_code == 200, publish.text

    verify = client.get(
        "/anchors/checkpoints/daily/2026-03-04/verify",
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
    assert report["valid"] is False
    assert report["external_anchor_verified"] is False
    assert report["external_anchor_reason"] == "external_anchor_mismatch"


def test_verify_independent_daily_checkpoint_passes_with_matching_external_payload(monkeypatch):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()

    monkeypatch.setenv("RELEASEGATE_ANCHORING_ENABLED", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_PROVIDER", "http_transparency")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_STRICT", "true")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_SIG_ALG", "ed25519")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_HTTP_URL", "https://anchor.example/api/root")
    monkeypatch.setenv("RELEASEGATE_ANCHOR_HTTP_CHECKPOINT_PUBLISH_URL", "https://anchor.example/api/checkpoints")
    _set_ed25519_env(monkeypatch)

    _record_attestation(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=304,
        commit_sha="jkl012",
        timestamp="2026-03-05T09:00:00Z",
    )

    import releasegate.anchoring.provider as provider_mod
    import releasegate.anchoring.independent_checkpoints as cp_mod

    checkpoint_holder = {}

    def _fake_post(url: str, json: dict, headers: dict, timeout: float):
        if "api/root" in url:
            return _response(201, {"log_index": "77", "root_hash": json["root_hash"]})
        if "api/checkpoints" in url:
            checkpoint_holder["checkpoint"] = json.get("checkpoint")
            return _response(201, {"external_ref": "cp-77", "fetch_url": "https://anchor.example/checkpoints/{external_ref}"})
        raise AssertionError(f"unexpected post url {url}")

    def _fake_get(url: str, headers: dict, timeout: float, params=None):
        return _response(200, {"checkpoint": checkpoint_holder.get("checkpoint") or {}})

    monkeypatch.setattr(provider_mod.requests, "post", _fake_post)
    monkeypatch.setattr(cp_mod.requests, "post", _fake_post)
    monkeypatch.setattr(cp_mod.requests, "get", _fake_get)

    publish = client.post(
        "/anchors/checkpoints/daily/2026-03-05/publish",
        json={"tenant_id": "tenant-a", "publish_anchor": True},
        headers=jwt_headers(
            tenant_id="tenant-a",
            roles=["admin"],
            scopes=["checkpoint:read", "proofpack:read"],
        ),
    )
    assert publish.status_code == 200, publish.text
    published = publish.json()
    assert ((published.get("signature") or {}).get("algorithm")) == "ed25519"
    assert ((published.get("signature") or {}).get("public_key")) != ""

    verify = client.get(
        "/anchors/checkpoints/daily/2026-03-05/verify",
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
    assert report["signature_valid"] is True
    assert report["external_anchor_verified"] is True
    assert report["valid"] is True
