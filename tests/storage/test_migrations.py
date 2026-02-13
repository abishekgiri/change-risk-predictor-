import sqlite3
import tempfile

import pytest

from releasegate.config import DB_PATH
from releasegate.storage import migrations as storage_migrations
from releasegate.storage.schema import init_db


def test_forward_only_migrations_applied_and_tenant_columns_present():
    current = init_db()
    assert current.startswith("20260213_")

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
        assert "tenant_id" in override_cols
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

        cur.execute("PRAGMA table_info(audit_attestations)")
        attestation_info = cur.fetchall()
        attestation_pk = [row[1] for row in sorted((r for r in attestation_info if r[5] > 0), key=lambda r: r[5])]
        assert attestation_pk == ["tenant_id", "attestation_id"]

        cur.execute("PRAGMA table_info(audit_transparency_log)")
        transparency_info = cur.fetchall()
        transparency_cols = {row[1] for row in transparency_info}
        transparency_pk = [row[1] for row in sorted((r for r in transparency_info if r[5] > 0), key=lambda r: r[5])]
        assert "tenant_id" in transparency_cols
        assert transparency_pk == ["tenant_id", "attestation_id"]

        cur.execute("SELECT current_version, migration_id FROM schema_state WHERE id = 1")
        state = cur.fetchone()
        assert state is not None
        assert state[0] == "20260213_011_attestations_and_transparency_log"
        assert state[1] == "20260213_011_attestations_and_transparency_log"
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
