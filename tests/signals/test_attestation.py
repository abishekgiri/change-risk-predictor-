from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from releasegate.config import DB_PATH
from releasegate.signals.attestation import (
    attest_signal,
    compute_signal_hash,
    evaluate_signal_attestation,
    get_latest_signal_attestation,
    resolve_signal_attestation_policy,
)
from releasegate.storage.schema import init_db


def _reset_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def test_signal_attestation_insert_and_latest_lookup():
    _reset_db()
    tenant_id = "tenant-signal-a"
    computed_at = datetime.now(timezone.utc)
    expires_at = computed_at + timedelta(hours=24)
    payload = {"risk_level": "HIGH", "risk_score": 87, "reasons": ["CHANGE_SIZE"]}
    canonical = {
        "signal_type": "risk_eval",
        "signal_source": "risk-engine",
        "subject_type": "jira_issue",
        "subject_id": "RG-999",
        "computed_at": computed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "payload": payload,
    }
    signal_hash = compute_signal_hash(canonical)
    created = attest_signal(
        tenant_id=tenant_id,
        signal_type="risk_eval",
        signal_source="risk-engine",
        subject_type="jira_issue",
        subject_id="RG-999",
        computed_at=computed_at.isoformat(),
        expires_at=expires_at.isoformat(),
        payload=payload,
        signal_hash=signal_hash,
    )
    assert created["signal_hash"] == signal_hash
    latest = get_latest_signal_attestation(
        tenant_id=tenant_id,
        signal_type="risk_eval",
        subject_type="jira_issue",
        subject_id="RG-999",
    )
    assert latest is not None
    assert latest["signal_id"] == created["signal_id"]
    assert latest["payload_json"]["risk_score"] == 87


def test_signal_attestation_policy_blocks_missing_required_attestation():
    _reset_db()
    policy = resolve_signal_attestation_policy(
        policy_overrides={"require_attestation_record": True},
        strict_enabled=True,
    )
    report = evaluate_signal_attestation(
        tenant_id="tenant-signal-b",
        signal_type="risk_eval",
        subject_type="jira_issue",
        subject_id="RG-1000",
        inline_signal=None,
        policy=policy,
    )
    assert report["stale"] is True
    assert report["should_block"] is True
    assert report["reason_code"] == "MISSING_SIGNAL"


def test_signal_attestation_policy_blocks_stale_or_invalid_hash():
    _reset_db()
    computed_at = datetime.now(timezone.utc) - timedelta(days=2)
    policy = resolve_signal_attestation_policy(
        policy_overrides={
            "require_attestation_record": False,
            "require_signal_source": True,
            "require_signal_hash": True,
            "require_expiration": True,
            "max_age_seconds": 3600,
        },
        strict_enabled=True,
    )
    stale_report = evaluate_signal_attestation(
        tenant_id="tenant-signal-c",
        signal_type="risk_eval",
        subject_type="jira_issue",
        subject_id="RG-1001",
        inline_signal={
            "signal_source": "risk-engine",
            "computed_at": computed_at.isoformat(),
            "expires_at": (computed_at + timedelta(hours=12)).isoformat(),
            "signal_hash": "sha256:not-real",
            "payload": {"risk_level": "LOW", "risk_score": 20},
        },
        policy=policy,
    )
    assert stale_report["stale"] is True
    assert stale_report["should_block"] is True
    assert stale_report["reason_code"] in {"INVALID_SIGNAL", "STALE_SIGNAL"}

