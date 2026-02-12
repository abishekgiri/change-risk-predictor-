import sqlite3

from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db


def test_forward_only_migrations_applied_and_tenant_columns_present():
    current = init_db()
    assert current.startswith("20260212_")

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

        cur.execute("PRAGMA table_info(audit_decisions)")
        decision_info = cur.fetchall()
        decision_cols = {row[1] for row in decision_info}
        decision_pk = [row[1] for row in sorted((r for r in decision_info if r[5] > 0), key=lambda r: r[5])]
        assert "tenant_id" in decision_cols
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

        cur.execute("SELECT current_version, migration_id FROM schema_state WHERE id = 1")
        state = cur.fetchone()
        assert state is not None
        assert state[0] == "20260212_007_tenant_composite_primary_keys"
        assert state[1] == "20260212_007_tenant_composite_primary_keys"
    finally:
        conn.close()
