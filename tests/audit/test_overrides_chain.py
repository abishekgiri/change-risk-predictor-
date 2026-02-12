import sqlite3
import uuid

from releasegate.audit.overrides import record_override, verify_override_chain
from releasegate.config import DB_PATH
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def test_override_chain_verification_valid():
    repo = f"chain-valid-{uuid.uuid4().hex[:8]}"
    record_override(repo=repo, pr_number=1, issue_key="T-1", decision_id="d1", actor="u1", reason="r1")
    record_override(repo=repo, pr_number=1, issue_key="T-1", decision_id="d2", actor="u2", reason="r2")

    result = verify_override_chain(repo=repo)
    assert result["valid"] is True
    assert result["checked"] == 2


def test_override_chain_verification_detects_bad_previous_hash():
    repo = f"chain-bad-{uuid.uuid4().hex[:8]}"
    tenant_id = resolve_tenant_id(None)
    record_override(repo=repo, pr_number=2, issue_key="T-2", decision_id="d1", actor="u1", reason="r1")

    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_overrides (
                override_id, tenant_id, decision_id, repo, pr_number, issue_key, actor, reason, previous_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"badrow-{uuid.uuid4().hex[:8]}",
                tenant_id,
                "d2",
                repo,
                2,
                "T-2",
                "u2",
                "tampered",
                "x" * 64,
                "y" * 64,
                "2030-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    result = verify_override_chain(repo=repo)
    assert result["valid"] is False
    assert result["reason"] in {"previous_hash mismatch", "event_hash mismatch"}


def test_override_record_is_idempotent_with_idempotency_key():
    repo = f"chain-idempotent-{uuid.uuid4().hex[:8]}"
    key = f"idem-{uuid.uuid4().hex}"

    first = record_override(
        repo=repo,
        pr_number=3,
        issue_key="T-3",
        decision_id="d1",
        actor="u1",
        reason="r1",
        idempotency_key=key,
    )
    second = record_override(
        repo=repo,
        pr_number=3,
        issue_key="T-3",
        decision_id="d1",
        actor="u1",
        reason="r1",
        idempotency_key=key,
    )

    assert first["override_id"] == second["override_id"]

    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_overrides WHERE idempotency_key = ?", (key,))
        count = cursor.fetchone()[0]
    finally:
        conn.close()

    assert count == 1
