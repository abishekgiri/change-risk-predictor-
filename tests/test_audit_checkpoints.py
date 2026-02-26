import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from releasegate.audit.checkpoints import (
    create_override_checkpoint,
    latest_override_checkpoint,
    verify_override_checkpoint,
)
from releasegate.audit.overrides import record_override
from releasegate.config import DB_PATH
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def test_create_and_verify_override_checkpoint(tmp_path):
    repo = f"checkpoint-{uuid.uuid4().hex[:8]}"
    key = "checkpoint-secret"
    store_dir = str(tmp_path)

    record_override(repo=repo, pr_number=1, issue_key="CP-1", decision_id="d1", actor="u1", reason="r1")
    record_override(repo=repo, pr_number=1, issue_key="CP-1", decision_id="d2", actor="u2", reason="r2")

    created = create_override_checkpoint(
        repo=repo,
        cadence="daily",
        pr=1,
        store_dir=store_dir,
        signing_key=key,
    )
    payload = created["payload"]

    verified = verify_override_checkpoint(
        repo=repo,
        cadence="daily",
        period_id=payload["period_id"],
        pr=1,
        store_dir=store_dir,
        signing_key=key,
    )

    assert created["created"] is True
    assert str(payload.get("checkpoint_hash") or "").startswith("sha256:")
    assert verified["exists"] is True
    assert verified["valid"] is True
    assert verified["signature_valid"] is True
    assert verified["checkpoint_hash_match"] is True
    assert verified["chain_valid"] is True
    assert verified["root_hash_match"] is True
    assert verified["event_count_match"] is True

    latest = latest_override_checkpoint(
        repo=repo,
        cadence="daily",
        store_dir=store_dir,
    )
    assert latest is not None
    assert latest.get("ids", {}).get("checkpoint_id") == created.get("ids", {}).get("checkpoint_id")


def test_checkpoint_creation_fails_for_invalid_chain(tmp_path):
    repo = f"checkpoint-bad-{uuid.uuid4().hex[:8]}"
    key = "checkpoint-secret"
    store_dir = str(tmp_path)
    tenant_id = resolve_tenant_id(None)

    record_override(repo=repo, pr_number=2, issue_key="CP-2", decision_id="d1", actor="u1", reason="r1")
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO audit_overrides (
                override_id, tenant_id, decision_id, repo, pr_number, issue_key, actor, reason, previous_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"tampered-{uuid.uuid4().hex[:8]}",
                tenant_id,
                "d2",
                repo,
                2,
                "CP-2",
                "u2",
                "tampered",
                "x" * 64,
                "y" * 64,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(ValueError, match="invalid chain"):
        create_override_checkpoint(
            repo=repo,
            cadence="daily",
            pr=2,
            store_dir=store_dir,
            signing_key=key,
        )
