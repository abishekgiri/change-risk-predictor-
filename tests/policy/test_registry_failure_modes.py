import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from releasegate.config import DB_PATH
from releasegate.policy.registry import create_registry_policy, resolve_registry_policy
from releasegate.storage.schema import init_db


@pytest.fixture
def clean_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def _seed_policy(tenant_id: str) -> None:
    create_registry_policy(
        tenant_id=tenant_id,
        scope_type="transition",
        scope_id="2",
        policy_json={"required_approvals": 2, "strict_fail_closed": True, "policy_source": "seed"},
        created_by="tester",
        status="ACTIVE",
    )


def _resolve_for_issue(tenant_id: str) -> dict:
    return resolve_registry_policy(
        tenant_id=tenant_id,
        org_id=tenant_id,
        project_id="PROJ",
        workflow_id="wf-release",
        transition_id="2",
        rollout_key="PROJ-123",
    )


def _set_cache_resolved_at(*, tenant_id: str, scope_key: str, resolved_at: datetime) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE tenant_policy_snapshot_cache
            SET resolved_at = ?
            WHERE tenant_id = ? AND scope_key = ?
            """,
            (resolved_at.isoformat(), tenant_id, scope_key),
        )
        conn.commit()
    finally:
        conn.close()


def _last_security_action() -> str:
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT action
            FROM security_audit_events
            ORDER BY created_at DESC
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        return str(row[0]) if row else ""
    finally:
        conn.close()


def test_resolve_registry_policy_reuses_cached_snapshot_when_live_resolution_fails(clean_db, monkeypatch):
    tenant_id = "tenant-cache-hit"
    _seed_policy(tenant_id)
    first = _resolve_for_issue(tenant_id)
    assert first["resolution_source"] == "control_plane"

    def _boom(**_: object) -> dict:
        raise RuntimeError("control plane unavailable")

    monkeypatch.setattr("releasegate.policy.registry._resolve_registry_policy_live", _boom)
    second = _resolve_for_issue(tenant_id)
    assert second["resolution_source"] == "cache"
    assert second["cache_state"] == "fresh"
    assert second["effective_policy_hash"] == first["effective_policy_hash"]
    assert _last_security_action() == "policy.snapshot.cache_hit"


def test_resolve_registry_policy_uses_grace_window_for_stale_snapshot(clean_db, monkeypatch):
    tenant_id = "tenant-cache-grace"
    monkeypatch.setenv("RELEASEGATE_POLICY_SNAPSHOT_CACHE_TTL_SECONDS", "1")
    monkeypatch.setenv("RELEASEGATE_POLICY_GRACE_WINDOW_SECONDS", "300")
    _seed_policy(tenant_id)
    first = _resolve_for_issue(tenant_id)

    stale_time = datetime.now(timezone.utc) - timedelta(seconds=30)
    _set_cache_resolved_at(
        tenant_id=tenant_id,
        scope_key=str(first["cache_scope_key"]),
        resolved_at=stale_time,
    )

    def _boom(**_: object) -> dict:
        raise RuntimeError("control plane unavailable")

    monkeypatch.setattr("releasegate.policy.registry._resolve_registry_policy_live", _boom)
    second = _resolve_for_issue(tenant_id)
    assert second["resolution_source"] == "cache"
    assert second["cache_state"] == "stale_grace"
    assert second["effective_policy_hash"] == first["effective_policy_hash"]
    assert _last_security_action() == "policy.snapshot.cache_stale_grace_used"


def test_resolve_registry_policy_fails_closed_after_cache_expiry(clean_db, monkeypatch):
    tenant_id = "tenant-cache-expired"
    monkeypatch.setenv("RELEASEGATE_POLICY_SNAPSHOT_CACHE_TTL_SECONDS", "1")
    monkeypatch.setenv("RELEASEGATE_POLICY_GRACE_WINDOW_SECONDS", "0")
    _seed_policy(tenant_id)
    first = _resolve_for_issue(tenant_id)

    expired_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    _set_cache_resolved_at(
        tenant_id=tenant_id,
        scope_key=str(first["cache_scope_key"]),
        resolved_at=expired_time,
    )

    def _boom(**_: object) -> dict:
        raise RuntimeError("control plane unavailable")

    monkeypatch.setattr("releasegate.policy.registry._resolve_registry_policy_live", _boom)
    with pytest.raises(RuntimeError, match="control plane unavailable"):
        _resolve_for_issue(tenant_id)
    assert _last_security_action() == "policy.snapshot.cache_expired_fail_closed"


def test_resolve_registry_policy_can_fail_open_when_allowlisted(clean_db, monkeypatch):
    tenant_id = "tenant-fail-open"
    monkeypatch.setenv("RELEASEGATE_FAIL_MODE", "open")
    monkeypatch.setenv("RELEASEGATE_FAIL_OPEN_ALLOWLIST", "*")
    monkeypatch.setenv("RELEASEGATE_POLICY_SNAPSHOT_CACHE_TTL_SECONDS", "1")
    monkeypatch.setenv("RELEASEGATE_POLICY_GRACE_WINDOW_SECONDS", "0")

    def _boom(**_: object) -> dict:
        raise RuntimeError("control plane unavailable")

    monkeypatch.setattr("releasegate.policy.registry._resolve_registry_policy_live", _boom)
    payload = _resolve_for_issue(tenant_id)
    assert payload["resolution_source"] == "fail_open"
    assert payload["fail_mode"] == "open"
    assert payload["effective_policy"] == {}
