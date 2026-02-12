from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Set


@dataclass(frozen=True)
class Migration:
    migration_id: str
    description: str
    apply: Callable[[any], None]


def _column_exists(cursor, table: str, column: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    return column in {row[1] for row in cursor.fetchall()}


def _table_pk_columns(cursor, table: str) -> List[str]:
    cursor.execute(f"PRAGMA table_info({table})")
    rows = cursor.fetchall()
    pk_rows = [row for row in rows if int(row[5]) > 0]
    pk_rows.sort(key=lambda row: int(row[5]))
    return [row[1] for row in pk_rows]


def _create_audit_decision_indexes(cursor) -> None:
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_context_id ON audit_decisions(context_id)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_tenant_repo_created ON audit_decisions(tenant_id, repo, created_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_tenant_repo_pr ON audit_decisions(tenant_id, repo, pr_number, created_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_tenant_status_created ON audit_decisions(tenant_id, release_status, created_at)"
    )
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_tenant_evaluation_key ON audit_decisions(tenant_id, evaluation_key)"
    )


def _create_audit_override_indexes(cursor) -> None:
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_overrides_tenant_repo_created ON audit_overrides(tenant_id, repo, created_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_overrides_tenant_repo_pr ON audit_overrides(tenant_id, repo, pr_number, created_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_overrides_tenant_target_created ON audit_overrides(tenant_id, target_type, target_id, created_at)"
    )
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_overrides_tenant_idempotency_key ON audit_overrides(tenant_id, idempotency_key)"
    )


def _create_checkpoint_indexes(cursor) -> None:
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_checkpoint_tenant_scope ON audit_checkpoints(tenant_id, repo, cadence, period_id, pr_number)"
    )


def _create_proof_pack_indexes(cursor) -> None:
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_proof_packs_tenant_decision ON audit_proof_packs(tenant_id, decision_id, created_at)"
    )


def _create_immutability_triggers(cursor) -> None:
    cursor.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_override_update
        BEFORE UPDATE ON audit_overrides
        BEGIN
            SELECT RAISE(FAIL, 'Override ledger is immutable: UPDATE not allowed');
        END;
        """
    )
    cursor.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_override_delete
        BEFORE DELETE ON audit_overrides
        BEGIN
            SELECT RAISE(FAIL, 'Override ledger is immutable: DELETE not allowed');
        END;
        """
    )
    cursor.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_audit_update
        BEFORE UPDATE ON audit_decisions
        BEGIN
            SELECT RAISE(FAIL, 'Audit logs are immutable: UPDATE not allowed');
        END;
        """
    )
    cursor.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
        BEFORE DELETE ON audit_decisions
        BEGIN
            SELECT RAISE(FAIL, 'Audit logs are immutable: DELETE not allowed');
        END;
        """
    )


def _create_schema_migrations_table(cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            current_version TEXT NOT NULL,
            migration_id TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )


def _applied_migration_ids(cursor) -> Set[str]:
    _create_schema_migrations_table(cursor)
    cursor.execute("SELECT migration_id FROM schema_migrations")
    return {row[0] for row in cursor.fetchall()}


def _mark_migration(cursor, migration_id: str, description: str) -> None:
    applied_at = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """
        INSERT INTO schema_migrations (migration_id, description, applied_at)
        VALUES (?, ?, ?)
        """,
        (migration_id, description, applied_at),
    )
    cursor.execute(
        """
        INSERT INTO schema_state (id, current_version, migration_id, updated_at)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            current_version=excluded.current_version,
            migration_id=excluded.migration_id,
            updated_at=excluded.updated_at
        """,
        (migration_id, migration_id, applied_at),
    )


def _migration_20260212_001_tenant_audit_decisions(cursor) -> None:
    if not _column_exists(cursor, "audit_decisions", "tenant_id"):
        cursor.execute(
            """
            ALTER TABLE audit_decisions
            ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'
            """
        )
    cursor.execute("DROP INDEX IF EXISTS idx_audit_evaluation_key")
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_tenant_evaluation_key
        ON audit_decisions(tenant_id, evaluation_key)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_tenant_repo_created
        ON audit_decisions(tenant_id, repo, created_at)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_tenant_repo_pr
        ON audit_decisions(tenant_id, repo, pr_number, created_at)
        """
    )


def _migration_20260212_002_tenant_audit_overrides(cursor) -> None:
    if not _column_exists(cursor, "audit_overrides", "tenant_id"):
        cursor.execute(
            """
            ALTER TABLE audit_overrides
            ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'
            """
        )
    cursor.execute("DROP INDEX IF EXISTS idx_overrides_idempotency_key")
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_overrides_tenant_idempotency_key
        ON audit_overrides(tenant_id, idempotency_key)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_overrides_tenant_repo_created
        ON audit_overrides(tenant_id, repo, created_at)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_overrides_tenant_repo_pr
        ON audit_overrides(tenant_id, repo, pr_number, created_at)
        """
    )


def _migration_20260212_003_policy_snapshots(cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_snapshots (
            tenant_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            policy_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, decision_id, policy_id)
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_snapshots_tenant_decision
        ON policy_snapshots(tenant_id, decision_id)
        """
    )


def _migration_20260212_004_checkpoint_and_proof_records(cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            repo TEXT NOT NULL,
            pr_number INTEGER,
            cadence TEXT NOT NULL,
            period_id TEXT NOT NULL,
            period_end TEXT NOT NULL,
            root_hash TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            signature_algorithm TEXT NOT NULL,
            signature_value TEXT NOT NULL,
            path TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_checkpoint_tenant_scope
        ON audit_checkpoints(tenant_id, repo, cadence, period_id, pr_number)
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_proof_packs (
            proof_pack_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            repo TEXT,
            pr_number INTEGER,
            output_format TEXT NOT NULL,
            bundle_version TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_proof_packs_tenant_decision
        ON audit_proof_packs(tenant_id, decision_id, created_at)
        """
    )


def _migration_20260212_005_tenant_constraints_and_policy_bundles(cursor) -> None:
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_decisions_tenant_decision
        ON audit_decisions(tenant_id, decision_id)
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_overrides_tenant_override
        ON audit_overrides(tenant_id, override_id)
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_checkpoints_tenant_checkpoint
        ON audit_checkpoints(tenant_id, checkpoint_id)
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_proof_packs_tenant_proof_pack
        ON audit_proof_packs(tenant_id, proof_pack_id)
        """
    )
    if not _column_exists(cursor, "audit_overrides", "target_type"):
        cursor.execute("ALTER TABLE audit_overrides ADD COLUMN target_type TEXT")
    if not _column_exists(cursor, "audit_overrides", "target_id"):
        cursor.execute("ALTER TABLE audit_overrides ADD COLUMN target_id TEXT")
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_overrides_tenant_target_created
        ON audit_overrides(tenant_id, target_type, target_id, created_at)
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_bundles (
            tenant_id TEXT NOT NULL,
            policy_bundle_hash TEXT NOT NULL,
            bundle_json TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, policy_bundle_hash)
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_bundles_tenant_active_created
        ON policy_bundles(tenant_id, is_active, created_at)
        """
    )


def _migration_20260212_006_metrics_events(cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS metrics_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            metric_value INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_metrics_events_tenant_metric_time
        ON metrics_events(tenant_id, metric_name, created_at)
        """
    )


def _migration_20260212_007_tenant_composite_primary_keys(cursor) -> None:
    if _table_pk_columns(cursor, "audit_decisions") != ["tenant_id", "decision_id"]:
        cursor.execute(
            """
            CREATE TABLE audit_decisions_new (
                tenant_id TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                context_id TEXT NOT NULL,
                repo TEXT NOT NULL,
                pr_number INTEGER,
                release_status TEXT NOT NULL,
                policy_bundle_hash TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                full_decision_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                evaluation_key TEXT,
                PRIMARY KEY (tenant_id, decision_id)
            )
            """
        )
        cursor.execute(
            """
            INSERT INTO audit_decisions_new (
                tenant_id, decision_id, context_id, repo, pr_number, release_status,
                policy_bundle_hash, engine_version, decision_hash, full_decision_json, created_at, evaluation_key
            )
            SELECT
                COALESCE(NULLIF(TRIM(tenant_id), ''), 'default') AS tenant_id,
                decision_id, context_id, repo, pr_number, release_status,
                policy_bundle_hash, engine_version, decision_hash, full_decision_json, created_at, evaluation_key
            FROM audit_decisions
            """
        )
        cursor.execute("DROP TABLE audit_decisions")
        cursor.execute("ALTER TABLE audit_decisions_new RENAME TO audit_decisions")

    if not _column_exists(cursor, "audit_overrides", "target_type"):
        cursor.execute("ALTER TABLE audit_overrides ADD COLUMN target_type TEXT")
    if not _column_exists(cursor, "audit_overrides", "target_id"):
        cursor.execute("ALTER TABLE audit_overrides ADD COLUMN target_id TEXT")

    if _table_pk_columns(cursor, "audit_overrides") != ["tenant_id", "override_id"]:
        cursor.execute(
            """
            CREATE TABLE audit_overrides_new (
                tenant_id TEXT NOT NULL,
                override_id TEXT NOT NULL,
                decision_id TEXT,
                repo TEXT NOT NULL,
                pr_number INTEGER,
                issue_key TEXT,
                actor TEXT,
                reason TEXT,
                target_type TEXT,
                target_id TEXT,
                idempotency_key TEXT,
                previous_hash TEXT,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, override_id)
            )
            """
        )
        cursor.execute(
            """
            INSERT INTO audit_overrides_new (
                tenant_id, override_id, decision_id, repo, pr_number, issue_key, actor, reason,
                target_type, target_id, idempotency_key, previous_hash, event_hash, created_at
            )
            SELECT
                COALESCE(NULLIF(TRIM(tenant_id), ''), 'default') AS tenant_id,
                override_id, decision_id, repo, pr_number, issue_key, actor, reason,
                COALESCE(target_type, 'pr') AS target_type,
                COALESCE(target_id, CASE WHEN pr_number IS NOT NULL THEN repo || '#' || pr_number ELSE repo END) AS target_id,
                idempotency_key, previous_hash, event_hash, created_at
            FROM audit_overrides
            """
        )
        cursor.execute("DROP TABLE audit_overrides")
        cursor.execute("ALTER TABLE audit_overrides_new RENAME TO audit_overrides")

    if _table_pk_columns(cursor, "audit_checkpoints") != ["tenant_id", "checkpoint_id"]:
        cursor.execute(
            """
            CREATE TABLE audit_checkpoints_new (
                tenant_id TEXT NOT NULL,
                checkpoint_id TEXT NOT NULL,
                repo TEXT NOT NULL,
                pr_number INTEGER,
                cadence TEXT NOT NULL,
                period_id TEXT NOT NULL,
                period_end TEXT NOT NULL,
                root_hash TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signature_value TEXT NOT NULL,
                path TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, checkpoint_id)
            )
            """
        )
        cursor.execute(
            """
            INSERT INTO audit_checkpoints_new (
                tenant_id, checkpoint_id, repo, pr_number, cadence, period_id, period_end, root_hash, event_count,
                signature_algorithm, signature_value, path, created_at
            )
            SELECT
                COALESCE(NULLIF(TRIM(tenant_id), ''), 'default') AS tenant_id,
                checkpoint_id, repo, pr_number, cadence, period_id, period_end, root_hash, event_count,
                signature_algorithm, signature_value, path, created_at
            FROM audit_checkpoints
            """
        )
        cursor.execute("DROP TABLE audit_checkpoints")
        cursor.execute("ALTER TABLE audit_checkpoints_new RENAME TO audit_checkpoints")

    if _table_pk_columns(cursor, "audit_proof_packs") != ["tenant_id", "proof_pack_id"]:
        cursor.execute(
            """
            CREATE TABLE audit_proof_packs_new (
                tenant_id TEXT NOT NULL,
                proof_pack_id TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                repo TEXT,
                pr_number INTEGER,
                output_format TEXT NOT NULL,
                bundle_version TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, proof_pack_id)
            )
            """
        )
        cursor.execute(
            """
            INSERT INTO audit_proof_packs_new (
                tenant_id, proof_pack_id, decision_id, repo, pr_number, output_format, bundle_version, created_at
            )
            SELECT
                COALESCE(NULLIF(TRIM(tenant_id), ''), 'default') AS tenant_id,
                proof_pack_id, decision_id, repo, pr_number, output_format, bundle_version, created_at
            FROM audit_proof_packs
            """
        )
        cursor.execute("DROP TABLE audit_proof_packs")
        cursor.execute("ALTER TABLE audit_proof_packs_new RENAME TO audit_proof_packs")

    _create_audit_decision_indexes(cursor)
    _create_audit_override_indexes(cursor)
    _create_checkpoint_indexes(cursor)
    _create_proof_pack_indexes(cursor)
    _create_immutability_triggers(cursor)


def _migration_20260212_008_security_auth_tables(cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            tenant_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            key_algorithm TEXT,
            key_iterations INTEGER,
            key_salt TEXT,
            roles_json TEXT NOT NULL,
            scopes_json TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (tenant_id, key_id)
        )
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_tenant_key_hash
        ON api_keys(tenant_id, key_hash)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_active
        ON api_keys(tenant_id, revoked_at, created_at)
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_nonces (
            tenant_id TEXT NOT NULL,
            integration_id TEXT NOT NULL DEFAULT 'legacy',
            key_id TEXT NOT NULL DEFAULT 'legacy',
            nonce TEXT NOT NULL,
            signature_hash TEXT NOT NULL,
            used_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, integration_id, nonce)
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_webhook_nonces_expires_at
        ON webhook_nonces(expires_at)
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_audit_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            auth_method TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_security_events_tenant_action_created
        ON security_audit_events(tenant_id, action, created_at)
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS checkpoint_signing_keys (
            tenant_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (tenant_id, key_id)
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_checkpoint_keys_tenant_active_created
        ON checkpoint_signing_keys(tenant_id, is_active, created_at)
        """
    )


def _migration_20260212_009_security_hardening(cursor) -> None:
    if not _column_exists(cursor, "api_keys", "key_algorithm"):
        cursor.execute("ALTER TABLE api_keys ADD COLUMN key_algorithm TEXT")
    if not _column_exists(cursor, "api_keys", "key_iterations"):
        cursor.execute("ALTER TABLE api_keys ADD COLUMN key_iterations INTEGER")
    if not _column_exists(cursor, "api_keys", "key_salt"):
        cursor.execute("ALTER TABLE api_keys ADD COLUMN key_salt TEXT")
    if not _column_exists(cursor, "api_keys", "is_enabled"):
        cursor.execute("ALTER TABLE api_keys ADD COLUMN is_enabled INTEGER NOT NULL DEFAULT 1")
    cursor.execute("UPDATE api_keys SET key_algorithm = COALESCE(NULLIF(TRIM(key_algorithm), ''), 'legacy_sha256')")
    cursor.execute("UPDATE api_keys SET key_iterations = COALESCE(key_iterations, 0)")
    cursor.execute("UPDATE api_keys SET key_salt = COALESCE(key_salt, '')")
    cursor.execute("UPDATE api_keys SET is_enabled = COALESCE(is_enabled, CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END)")
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_global_key_id
        ON api_keys(key_id)
        """
    )

    nonce_has_integration = _column_exists(cursor, "webhook_nonces", "integration_id")
    nonce_has_key_id = _column_exists(cursor, "webhook_nonces", "key_id")
    nonce_pk = _table_pk_columns(cursor, "webhook_nonces")
    expected_pk = ["tenant_id", "integration_id", "nonce"]
    if nonce_pk != expected_pk or not nonce_has_integration or not nonce_has_key_id:
        integration_expr = "COALESCE(NULLIF(TRIM(integration_id), ''), 'legacy')" if nonce_has_integration else "'legacy'"
        key_expr = "COALESCE(NULLIF(TRIM(key_id), ''), 'legacy')" if nonce_has_key_id else "'legacy'"
        cursor.execute(
            """
            CREATE TABLE webhook_nonces_new (
                tenant_id TEXT NOT NULL,
                integration_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                signature_hash TEXT NOT NULL,
                used_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, integration_id, nonce)
            )
            """
        )
        cursor.execute(
            f"""
            INSERT INTO webhook_nonces_new (
                tenant_id, integration_id, key_id, nonce, signature_hash, used_at, expires_at
            )
            SELECT
                COALESCE(NULLIF(TRIM(tenant_id), ''), 'default') AS tenant_id,
                {integration_expr} AS integration_id,
                {key_expr} AS key_id,
                nonce,
                signature_hash,
                used_at,
                expires_at
            FROM webhook_nonces
            """
        )
        cursor.execute("DROP TABLE webhook_nonces")
        cursor.execute("ALTER TABLE webhook_nonces_new RENAME TO webhook_nonces")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_nonces_expires_at ON webhook_nonces(expires_at)")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_signing_keys (
            tenant_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            encrypted_secret TEXT NOT NULL,
            secret_hash TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (tenant_id, integration_id, key_id)
        )
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_webhook_signing_keys_key_id
        ON webhook_signing_keys(key_id)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_webhook_signing_keys_tenant_integration_active
        ON webhook_signing_keys(tenant_id, integration_id, is_active, created_at)
        """
    )


def _migration_20260212_010_phase4_idempotency_and_hashes(cursor) -> None:
    if not _column_exists(cursor, "audit_decisions", "input_hash"):
        cursor.execute("ALTER TABLE audit_decisions ADD COLUMN input_hash TEXT")
    if not _column_exists(cursor, "audit_decisions", "policy_hash"):
        cursor.execute("ALTER TABLE audit_decisions ADD COLUMN policy_hash TEXT")
    if not _column_exists(cursor, "audit_decisions", "replay_hash"):
        cursor.execute("ALTER TABLE audit_decisions ADD COLUMN replay_hash TEXT")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS idempotency_keys (
            tenant_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            idem_key TEXT NOT NULL,
            request_fingerprint TEXT NOT NULL,
            status TEXT NOT NULL,
            response_json TEXT,
            resource_type TEXT,
            resource_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, operation, idem_key)
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_idempotency_keys_tenant_operation_created
        ON idempotency_keys(tenant_id, operation, created_at)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires_at
        ON idempotency_keys(expires_at)
        """
    )

    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_overrides_chain_prev
        ON audit_overrides(tenant_id, repo, previous_hash)
        """
    )


MIGRATIONS: List[Migration] = [
    Migration(
        migration_id="20260212_001_tenant_audit_decisions",
        description="Add tenant identity to audit_decisions and tenant-safe indexes.",
        apply=_migration_20260212_001_tenant_audit_decisions,
    ),
    Migration(
        migration_id="20260212_002_tenant_audit_overrides",
        description="Add tenant identity to audit_overrides and tenant-safe idempotency indexes.",
        apply=_migration_20260212_002_tenant_audit_overrides,
    ),
    Migration(
        migration_id="20260212_003_policy_snapshots",
        description="Create policy_snapshots table for tenant-bound policy records.",
        apply=_migration_20260212_003_policy_snapshots,
    ),
    Migration(
        migration_id="20260212_004_checkpoint_and_proof_records",
        description="Create tenant-scoped checkpoint and proof-pack record tables.",
        apply=_migration_20260212_004_checkpoint_and_proof_records,
    ),
    Migration(
        migration_id="20260212_005_tenant_constraints_and_policy_bundles",
        description="Add tenant-safe unique constraints, override target keys, and policy_bundles table.",
        apply=_migration_20260212_005_tenant_constraints_and_policy_bundles,
    ),
    Migration(
        migration_id="20260212_006_metrics_events",
        description="Add tenant-scoped append-only metrics_events table.",
        apply=_migration_20260212_006_metrics_events,
    ),
    Migration(
        migration_id="20260212_007_tenant_composite_primary_keys",
        description="Rebuild audit tables to enforce tenant-scoped composite primary keys.",
        apply=_migration_20260212_007_tenant_composite_primary_keys,
    ),
    Migration(
        migration_id="20260212_008_security_auth_tables",
        description="Add auth, webhook nonce, and security audit tables.",
        apply=_migration_20260212_008_security_auth_tables,
    ),
    Migration(
        migration_id="20260212_009_security_hardening",
        description="Harden auth schema with webhook signing keys, nonce scope, and PBKDF2 api-key fields.",
        apply=_migration_20260212_009_security_hardening,
    ),
    Migration(
        migration_id="20260212_010_phase4_idempotency_and_hashes",
        description="Add phase-4 idempotency key records, deterministic decision hashes, and chain-integrity indexes.",
        apply=_migration_20260212_010_phase4_idempotency_and_hashes,
    ),
]


def pending_sqlite_migrations(conn) -> List[str]:
    cursor = conn.cursor()
    _create_schema_migrations_table(cursor)
    applied = _applied_migration_ids(cursor)
    return [m.migration_id for m in MIGRATIONS if m.migration_id not in applied]


def apply_sqlite_migrations(conn, *, auto_apply: bool = True) -> str:
    """
    Apply forward-only migrations in order and return current schema version id.
    """
    cursor = conn.cursor()
    _create_schema_migrations_table(cursor)
    # Persist migration bookkeeping tables before transactional migration work.
    conn.commit()
    applied = _applied_migration_ids(cursor)
    pending = [m for m in MIGRATIONS if m.migration_id not in applied]
    if pending and not auto_apply:
        raise RuntimeError(
            f"Database schema is behind. Pending migrations: {[m.migration_id for m in pending]}"
        )
    current = "base"

    try:
        cursor.execute("BEGIN IMMEDIATE")

        for migration in pending:
            current = migration.migration_id
            migration.apply(cursor)
            _mark_migration(cursor, migration.migration_id, migration.description)

        if not pending and MIGRATIONS:
            current = MIGRATIONS[-1].migration_id
            cursor.execute(
                """
                INSERT INTO schema_state (id, current_version, migration_id, updated_at)
                VALUES (1, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (current, current, datetime.now(timezone.utc).isoformat()),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return current if MIGRATIONS else "base"
