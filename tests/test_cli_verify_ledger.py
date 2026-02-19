from __future__ import annotations

import os
import sys
import uuid

from releasegate.audit.checkpoints import create_jira_lock_checkpoint
from releasegate.cli import build_parser, main
from releasegate.config import DB_PATH
from releasegate.integrations.jira.lock_store import apply_transition_lock_update
from releasegate.storage.schema import init_db


def _seed_lock_chain(*, tenant: str, issue: str) -> str:
    chain_id = f"jira-lock:{issue}"
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=True,
        reason_codes=["POLICY_BLOCKED"],
        decision_id="d-cli-1",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="abishekgiri/change-risk-predictor-",
        pr_number=28,
        actor="admin@example.com",
        context={"transition_id": "2"},
    )
    apply_transition_lock_update(
        tenant_id=tenant,
        issue_key=issue,
        desired_locked=False,
        reason_codes=["POLICY_ALLOWED"],
        decision_id="d-cli-2",
        policy_hash="ph",
        policy_resolution_hash="prh",
        repo="abishekgiri/change-risk-predictor-",
        pr_number=28,
        actor="admin@example.com",
        context={"transition_id": "2"},
    )
    return chain_id


def test_cli_parser_includes_verify_lock_ledger():
    parser = build_parser()
    args = parser.parse_args(["verify", "lock-ledger", "--tenant", "tenant-test", "--chain", "jira-lock:RG-1"])
    assert args.cmd == "verify"
    assert args.verify_cmd == "lock-ledger"


def test_cli_verify_lock_ledger_returns_zero_for_valid_chain(monkeypatch):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    tenant = "tenant-test"
    issue = f"RG-CLI-{uuid.uuid4().hex[:8]}"
    chain_id = _seed_lock_chain(tenant=tenant, issue=issue)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releasegate",
            "verify",
            "lock-ledger",
            "--tenant",
            tenant,
            "--chain",
            chain_id,
            "--format",
            "json",
        ],
    )
    rc = main()
    assert rc == 0


def test_cli_verify_checkpoints_range_returns_zero_for_valid_checkpoint(monkeypatch, tmp_path):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    tenant = "tenant-test"
    issue = f"RG-CLI-{uuid.uuid4().hex[:8]}"
    chain_id = _seed_lock_chain(tenant=tenant, issue=issue)

    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "cli-checkpoint-key")
    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID", "cli-key-id")
    checkpoint = create_jira_lock_checkpoint(
        chain_id=chain_id,
        cadence="daily",
        tenant_id=tenant,
        store_dir=str(tmp_path / "checkpoints"),
    )
    period = checkpoint["payload"]["period_id"]

    monkeypatch.setenv("RELEASEGATE_CHECKPOINT_STORE_DIR", str(tmp_path / "checkpoints"))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releasegate",
            "verify",
            "checkpoints",
            "--tenant",
            tenant,
            "--from",
            period,
            "--to",
            period,
            "--chain",
            chain_id,
            "--format",
            "json",
        ],
    )
    rc = main()
    assert rc == 0
