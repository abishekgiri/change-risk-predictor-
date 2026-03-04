from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from tests.auth_helpers import jwt_headers
from releasegate.config import DB_PATH
from releasegate.server import app
from releasegate.storage.schema import init_db


client = TestClient(app)


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def test_signal_attestation_endpoints_store_and_read_latest():
    _reset_db()
    tenant_id = "tenant-signal-api"
    computed_at = datetime.now(timezone.utc)
    expires_at = computed_at + timedelta(hours=24)

    create_resp = client.post(
        "/signals/attest",
        json={
            "tenant_id": tenant_id,
            "signal_type": "risk_eval",
            "signal_source": "risk-engine",
            "subject_type": "jira_issue",
            "subject_id": "RG-2001",
            "computed_at": computed_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "payload": {"risk_level": "MEDIUM", "risk_score": 64},
        },
        headers=jwt_headers(tenant_id=tenant_id, roles=["admin"], scopes=["enforcement:write"]),
    )
    assert create_resp.status_code == 200, create_resp.text
    created = create_resp.json()
    assert created["ok"] is True
    assert created["signal_type"] == "risk_eval"

    latest_resp = client.get(
        "/signals/latest",
        params={
            "tenant_id": tenant_id,
            "signal_type": "risk_eval",
            "subject_type": "jira_issue",
            "subject_id": "RG-2001",
        },
        headers=jwt_headers(tenant_id=tenant_id, roles=["auditor"], scopes=["policy:read"]),
    )
    assert latest_resp.status_code == 200, latest_resp.text
    latest = latest_resp.json()
    assert latest["ok"] is True
    item = latest["item"]
    assert item["signal_id"] == created["signal_id"]
    assert item["payload_json"]["risk_score"] == 64


def test_signal_attestation_latest_is_tenant_scoped():
    _reset_db()
    tenant_a = "tenant-signal-api-a"
    tenant_b = "tenant-signal-api-b"
    computed_at = datetime.now(timezone.utc)
    expires_at = computed_at + timedelta(hours=24)

    created = client.post(
        "/signals/attest",
        json={
            "tenant_id": tenant_a,
            "signal_type": "risk_eval",
            "signal_source": "risk-engine",
            "subject_type": "jira_issue",
            "subject_id": "RG-2002",
            "computed_at": computed_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "payload": {"risk_level": "LOW", "risk_score": 20},
        },
        headers=jwt_headers(tenant_id=tenant_a, roles=["admin"], scopes=["enforcement:write"]),
    )
    assert created.status_code == 200, created.text

    denied = client.get(
        "/signals/latest",
        params={
            "tenant_id": tenant_a,
            "signal_type": "risk_eval",
            "subject_type": "jira_issue",
            "subject_id": "RG-2002",
        },
        headers=jwt_headers(tenant_id=tenant_b, roles=["auditor"], scopes=["policy:read"]),
    )
    assert denied.status_code == 403
