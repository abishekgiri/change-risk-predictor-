import sqlite3
import tempfile

import pytest

from releasegate.config import DB_PATH
from releasegate.storage import migrations as storage_migrations
from releasegate.storage.schema import init_db


def test_forward_only_migrations_applied_and_tenant_columns_present():
    current = init_db()
    assert current.startswith("202602")

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("SELECT migration_id FROM schema_migrations ORDER BY migration_id ASC")
        migration_ids = [row[0] for row in cur.fetchall()]
        assert "20260212_001_tenant_audit_decisions" in migration_ids
        assert "20260212_002_tenant_audit_overrides" in migration_ids
        assert "20260212_003_policy_snapshots" in migration_ids
        assert "20260212_004_checkpoint_and_proof_records" in migration_ids
        assert "20260212_005_tenant_constraints_and_policy_bundles" in migration_ids
        assert "20260212_006_metrics_events" in migration_ids
        assert "20260212_007_tenant_composite_primary_keys" in migration_ids
        assert "20260212_008_security_auth_tables" in migration_ids
        assert "20260212_009_security_hardening" in migration_ids
        assert "20260212_010_phase4_idempotency_and_hashes" in migration_ids
        assert "20260213_011_attestations_and_transparency_log" in migration_ids
        assert "20260213_012_transparency_engine_build" in migration_ids
        assert "20260213_013_transparency_daily_roots" in migration_ids
        assert "20260214_014_attestation_immutability" in migration_ids
        assert "20260218_015_jira_lock_ledger" in migration_ids
        assert "20260218_016_decision_external_refs" in migration_ids
        assert "20260219_017_policy_snapshot_rollout" in migration_ids
        assert "20260219_018_lock_chain_governance" in migration_ids
        assert "20260220_019_replay_and_evidence_graph" in migration_ids
        assert "20260220_020_replay_status_column" in migration_ids
        assert "20260220_021_override_expiry_metadata" in migration_ids
        assert "20260220_022_policy_registry_control_plane" in migration_ids
        assert "20260226_023_policy_lifecycle_state_machine" in migration_ids

        cur.execute("PRAGMA table_info(audit_decisions)")
        decision_info = cur.fetchall()
        decision_cols = {row[1] for row in decision_info}
        decision_pk = [row[1] for row in sorted((r for r in decision_info if r[5] > 0), key=lambda r: r[5])]
        assert "tenant_id" in decision_cols
        assert "input_hash" in decision_cols
        assert "policy_hash" in decision_cols
        assert "replay_hash" in decision_cols
        assert decision_pk == ["tenant_id", "decision_id"]

        cur.execute("PRAGMA table_info(audit_overrides)")
        override_info = cur.fetchall()
        override_cols = {row[1] for row in override_info}
        override_pk = [row[1] for row in sorted((r for r in override_info if r[5] > 0), key=lambda r: r[5])]
        assert {
            "tenant_id",
            "ttl_seconds",
            "expires_at",
            "requested_by",
            "approved_by",
        } <= override_cols
        assert override_pk == ["tenant_id", "override_id"]

        cur.execute("PRAGMA table_info(audit_checkpoints)")
        checkpoint_info = cur.fetchall()
        checkpoint_pk = [row[1] for row in sorted((r for r in checkpoint_info if r[5] > 0), key=lambda r: r[5])]
        assert checkpoint_pk == ["tenant_id", "checkpoint_id"]

        cur.execute("PRAGMA table_info(audit_proof_packs)")
        proof_pack_info = cur.fetchall()
        proof_pack_pk = [row[1] for row in sorted((r for r in proof_pack_info if r[5] > 0), key=lambda r: r[5])]
        assert proof_pack_pk == ["tenant_id", "proof_pack_id"]

        cur.execute("PRAGMA table_info(api_keys)")
        api_keys_info = cur.fetchall()
        api_keys_pk = [row[1] for row in sorted((r for r in api_keys_info if r[5] > 0), key=lambda r: r[5])]
        assert api_keys_pk == ["tenant_id", "key_id"]

        cur.execute("PRAGMA table_info(webhook_nonces)")
        nonces_info = cur.fetchall()
        nonces_pk = [row[1] for row in sorted((r for r in nonces_info if r[5] > 0), key=lambda r: r[5])]
        assert nonces_pk == ["tenant_id", "integration_id", "nonce"]

        cur.execute("PRAGMA table_info(security_audit_events)")
        sec_info = cur.fetchall()
        sec_pk = [row[1] for row in sorted((r for r in sec_info if r[5] > 0), key=lambda r: r[5])]
        assert sec_pk == ["tenant_id", "event_id"]

        cur.execute("PRAGMA table_info(checkpoint_signing_keys)")
        checkpoint_keys_info = cur.fetchall()
        checkpoint_keys_pk = [row[1] for row in sorted((r for r in checkpoint_keys_info if r[5] > 0), key=lambda r: r[5])]
        assert checkpoint_keys_pk == ["tenant_id", "key_id"]

        cur.execute("PRAGMA table_info(webhook_signing_keys)")
        webhook_keys_info = cur.fetchall()
        webhook_keys_pk = [row[1] for row in sorted((r for r in webhook_keys_info if r[5] > 0), key=lambda r: r[5])]
        assert webhook_keys_pk == ["tenant_id", "integration_id", "key_id"]

        cur.execute("PRAGMA table_info(idempotency_keys)")
        idem_info = cur.fetchall()
        idem_pk = [row[1] for row in sorted((r for r in idem_info if r[5] > 0), key=lambda r: r[5])]
        assert idem_pk == ["tenant_id", "operation", "idem_key"]

        cur.execute("PRAGMA table_info(policy_registry_entries)")
        policy_registry_info = cur.fetchall()
        policy_registry_cols = {row[1] for row in policy_registry_info}
        assert "archived_at" in policy_registry_cols

        cur.execute("PRAGMA table_info(policy_registry_events)")
        policy_event_info = cur.fetchall()
        policy_event_pk = [row[1] for row in sorted((r for r in policy_event_info if r[5] > 0), key=lambda r: r[5])]
        assert policy_event_pk == ["tenant_id", "event_id"]

        cur.execute("PRAGMA table_info(audit_attestations)")
        attestation_info = cur.fetchall()
        attestation_pk = [row[1] for row in sorted((r for r in attestation_info if r[5] > 0), key=lambda r: r[5])]
        assert attestation_pk == ["tenant_id", "attestation_id"]

        cur.execute("PRAGMA table_info(audit_transparency_log)")
        transparency_info = cur.fetchall()
        transparency_cols = {row[1] for row in transparency_info}
        transparency_pk = [row[1] for row in sorted((r for r in transparency_info if r[5] > 0), key=lambda r: r[5])]
        assert "tenant_id" in transparency_cols
        assert "engine_git_sha" in transparency_cols
        assert "engine_version" in transparency_cols
        assert transparency_pk == ["tenant_id", "attestation_id"]

        cur.execute("PRAGMA table_info(audit_transparency_roots)")
        root_info = cur.fetchall()
        root_cols = {row[1] for row in root_info}
        root_pk = [row[1] for row in sorted((r for r in root_info if r[5] > 0), key=lambda r: r[5])]
        assert "tenant_id" in root_cols
        assert "date_utc" in root_cols
        assert "leaf_count" in root_cols
        assert "root_hash" in root_cols
        assert root_pk == ["tenant_id", "date_utc"]

        cur.execute("PRAGMA table_info(jira_lock_events)")
        lock_event_info = cur.fetchall()
        lock_event_cols = {row[1] for row in lock_event_info}
        lock_event_pk = [row[1] for row in sorted((r for r in lock_event_info if r[5] > 0), key=lambda r: r[5])]
        assert {
            "tenant_id",
            "event_id",
            "issue_key",
            "event_type",
            "chain_id",
            "seq",
            "prev_hash",
            "event_hash",
            "ttl_seconds",
            "expires_at",
            "justification",
            "context_json",
        } <= lock_event_cols
        assert lock_event_pk == ["tenant_id", "event_id"]

        cur.execute("PRAGMA table_info(jira_issue_locks_current)")
        lock_current_info = cur.fetchall()
        lock_current_cols = {row[1] for row in lock_current_info}
        lock_current_pk = [row[1] for row in sorted((r for r in lock_current_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "issue_key", "locked"} <= lock_current_cols
        assert lock_current_pk == ["tenant_id", "issue_key"]

        cur.execute("PRAGMA table_info(audit_decision_refs)")
        ref_info = cur.fetchall()
        ref_cols = {row[1] for row in ref_info}
        ref_pk = [row[1] for row in sorted((r for r in ref_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "decision_id", "repo", "ref_type", "ref_value"} <= ref_cols
        assert ref_pk == ["tenant_id", "decision_id", "ref_type", "ref_value"]

        cur.execute("PRAGMA table_info(policy_resolved_snapshots)")
        snap_info = cur.fetchall()
        snap_cols = {row[1] for row in snap_info}
        snap_pk = [row[1] for row in sorted((r for r in snap_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "snapshot_id", "policy_hash", "snapshot_json"} <= snap_cols
        assert snap_pk == ["tenant_id", "snapshot_id"]

        cur.execute("PRAGMA table_info(policy_decision_records)")
        pdr_info = cur.fetchall()
        pdr_cols = {row[1] for row in pdr_info}
        pdr_pk = [row[1] for row in sorted((r for r in pdr_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "decision_id", "snapshot_id", "policy_hash", "decision"} <= pdr_cols
        assert pdr_pk == ["tenant_id", "decision_id"]

        cur.execute("PRAGMA table_info(policy_releases)")
        releases_info = cur.fetchall()
        releases_cols = {row[1] for row in releases_info}
        releases_pk = [row[1] for row in sorted((r for r in releases_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "release_id", "policy_id", "snapshot_id", "target_env", "state"} <= releases_cols
        assert releases_pk == ["tenant_id", "release_id"]

        cur.execute("PRAGMA table_info(active_policy_pointers)")
        pointers_info = cur.fetchall()
        pointers_cols = {row[1] for row in pointers_info}
        pointers_pk = [row[1] for row in sorted((r for r in pointers_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "policy_id", "target_env", "active_release_id"} <= pointers_cols
        assert pointers_pk == ["tenant_id", "policy_id", "target_env"]

        cur.execute("PRAGMA table_info(audit_lock_checkpoints)")
        lock_cp_info = cur.fetchall()
        lock_cp_cols = {row[1] for row in lock_cp_info}
        lock_cp_pk = [row[1] for row in sorted((r for r in lock_cp_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "checkpoint_id", "chain_id", "head_seq", "head_hash"} <= lock_cp_cols
        assert lock_cp_pk == ["tenant_id", "checkpoint_id"]

        cur.execute("PRAGMA table_info(governance_override_metrics_daily)")
        metrics_info = cur.fetchall()
        metrics_cols = {row[1] for row in metrics_info}
        metrics_pk = [row[1] for row in sorted((r for r in metrics_info if r[5] > 0), key=lambda r: r[5])]
        assert {
            "tenant_id",
            "date_utc",
            "chain_id",
            "actor",
            "overrides_total",
            "high_risk_overrides_total",
        } <= metrics_cols
        assert metrics_pk == ["tenant_id", "date_utc", "chain_id", "actor"]

        cur.execute("PRAGMA table_info(audit_decision_replays)")
        replay_info = cur.fetchall()
        replay_cols = {row[1] for row in replay_info}
        replay_pk = [row[1] for row in sorted((r for r in replay_info if r[5] > 0), key=lambda r: r[5])]
        assert {
            "tenant_id",
            "replay_id",
            "decision_id",
            "match",
            "status",
            "diff_json",
            "old_output_hash",
            "new_output_hash",
            "ran_engine_version",
        } <= replay_cols
        assert replay_pk == ["tenant_id", "replay_id"]

        cur.execute("PRAGMA table_info(evidence_nodes)")
        en_info = cur.fetchall()
        en_cols = {row[1] for row in en_info}
        en_pk = [row[1] for row in sorted((r for r in en_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "node_id", "type", "ref", "hash", "payload_json"} <= en_cols
        assert en_pk == ["tenant_id", "node_id"]

        cur.execute("PRAGMA table_info(evidence_edges)")
        ee_info = cur.fetchall()
        ee_cols = {row[1] for row in ee_info}
        ee_pk = [row[1] for row in sorted((r for r in ee_info if r[5] > 0), key=lambda r: r[5])]
        assert {"tenant_id", "edge_id", "from_node_id", "to_node_id", "type", "metadata_json"} <= ee_cols
        assert ee_pk == ["tenant_id", "edge_id"]

        cur.execute("PRAGMA table_info(policy_registry_entries)")
        pr_info = cur.fetchall()
        pr_cols = {row[1] for row in pr_info}
        pr_pk = [row[1] for row in sorted((r for r in pr_info if r[5] > 0), key=lambda r: r[5])]
        assert {
            "tenant_id",
            "policy_id",
            "scope_type",
            "scope_id",
            "version",
            "status",
            "policy_json",
            "policy_hash",
            "lint_errors_json",
            "lint_warnings_json",
            "rollout_percentage",
            "rollout_scope",
            "created_at",
            "created_by",
            "activated_at",
            "activated_by",
            "archived_at",
            "supersedes_policy_id",
        } <= pr_cols
        assert pr_pk == ["tenant_id", "policy_id"]

        cur.execute("SELECT current_version, migration_id FROM schema_state WHERE id = 1")
        state = cur.fetchone()
        assert state is not None
        latest = storage_migrations.MIGRATIONS[-1].migration_id
        assert state[0] == latest
        assert state[1] == latest
    finally:
        conn.close()


def test_sqlite_migration_batch_rolls_back_on_failure():
    fail_id = "99999999_fail_atomicity_check"

    def _failing_migration(cursor):
        cursor.execute("CREATE TABLE fail_marker_table (id INTEGER PRIMARY KEY, note TEXT)")
        cursor.execute("INSERT INTO fail_marker_table (note) VALUES ('should_rollback')")
        raise RuntimeError("intentional migration failure")

    bad = storage_migrations.Migration(
        migration_id=fail_id,
        description="intentional failure to validate rollback",
        apply=_failing_migration,
    )

    with tempfile.NamedTemporaryFile(suffix=".db") as temp:
        conn = sqlite3.connect(temp.name)
        original = storage_migrations.MIGRATIONS
        storage_migrations.MIGRATIONS = [bad]
        try:
            with pytest.raises(RuntimeError):
                storage_migrations.apply_sqlite_migrations(conn, auto_apply=True)

            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='fail_marker_table'")
            assert cur.fetchone() is None

            cur.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?",
                (fail_id,),
            )
            assert cur.fetchone()[0] == 0

            cur.execute("SELECT current_version, migration_id FROM schema_state WHERE id = 1")
            assert cur.fetchone() is None
        finally:
            storage_migrations.MIGRATIONS = original
            conn.close()
