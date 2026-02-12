from __future__ import annotations

from datetime import datetime, timezone
import os
import sqlite3

from releasegate.config import DB_PATH
from releasegate.storage.migrations import MIGRATIONS, apply_sqlite_migrations


SCHEMA_VERSION = "v5"


def _init_postgres_schema() -> str:
    dsn = os.getenv("RELEASEGATE_POSTGRES_DSN") or os.getenv("DATABASE_URL")
    if not dsn:
        raise ValueError("Postgres storage backend selected but RELEASEGATE_POSTGRES_DSN/DATABASE_URL is missing.")

    import psycopg2

    conn = psycopg2.connect(dsn)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_state (
            id INTEGER PRIMARY KEY,
            current_version TEXT NOT NULL,
            migration_id TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_decisions (
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
            created_at TIMESTAMPTZ NOT NULL,
            evaluation_key TEXT,
            PRIMARY KEY (tenant_id, decision_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_tenant_evaluation_key
        ON audit_decisions(tenant_id, evaluation_key)
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_decisions_tenant_decision
        ON audit_decisions(tenant_id, decision_id)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_overrides (
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
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, override_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_overrides_tenant_idempotency_key
        ON audit_overrides(tenant_id, idempotency_key)
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_overrides_tenant_override
        ON audit_overrides(tenant_id, override_id)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_overrides_tenant_target_created
        ON audit_overrides(tenant_id, target_type, target_id, created_at)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_snapshots (
            tenant_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            policy_json TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, decision_id, policy_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_checkpoints (
            tenant_id TEXT NOT NULL,
            checkpoint_id TEXT NOT NULL,
            repo TEXT NOT NULL,
            pr_number INTEGER,
            cadence TEXT NOT NULL,
            period_id TEXT NOT NULL,
            period_end TIMESTAMPTZ NOT NULL,
            root_hash TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            signature_algorithm TEXT NOT NULL,
            signature_value TEXT NOT NULL,
            path TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, checkpoint_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_checkpoints_tenant_checkpoint
        ON audit_checkpoints(tenant_id, checkpoint_id)
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_checkpoint_tenant_scope
        ON audit_checkpoints(tenant_id, repo, cadence, period_id, pr_number)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_proof_packs (
            tenant_id TEXT NOT NULL,
            proof_pack_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            repo TEXT,
            pr_number INTEGER,
            output_format TEXT NOT NULL,
            bundle_version TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, proof_pack_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_proof_packs_tenant_proof_pack
        ON audit_proof_packs(tenant_id, proof_pack_id)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_proof_packs_tenant_decision
        ON audit_proof_packs(tenant_id, decision_id, created_at)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_bundles (
            tenant_id TEXT NOT NULL,
            policy_bundle_hash TEXT NOT NULL,
            bundle_json JSONB NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, policy_bundle_hash)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_bundles_tenant_active_created
        ON policy_bundles(tenant_id, is_active, created_at)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS metrics_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            metric_value INTEGER NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            metadata_json JSONB,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_metrics_events_tenant_metric_time
        ON metrics_events(tenant_id, metric_name, created_at)
        """
    )
    # Ensure existing Postgres deployments are hardened to tenant-scoped PKs.
    cur.execute("ALTER TABLE audit_decisions ADD COLUMN IF NOT EXISTS tenant_id TEXT")
    cur.execute("ALTER TABLE audit_overrides ADD COLUMN IF NOT EXISTS tenant_id TEXT")
    cur.execute("ALTER TABLE audit_checkpoints ADD COLUMN IF NOT EXISTS tenant_id TEXT")
    cur.execute("ALTER TABLE audit_proof_packs ADD COLUMN IF NOT EXISTS tenant_id TEXT")
    cur.execute("UPDATE audit_decisions SET tenant_id = 'default' WHERE tenant_id IS NULL OR btrim(tenant_id) = ''")
    cur.execute("UPDATE audit_overrides SET tenant_id = 'default' WHERE tenant_id IS NULL OR btrim(tenant_id) = ''")
    cur.execute("UPDATE audit_checkpoints SET tenant_id = 'default' WHERE tenant_id IS NULL OR btrim(tenant_id) = ''")
    cur.execute("UPDATE audit_proof_packs SET tenant_id = 'default' WHERE tenant_id IS NULL OR btrim(tenant_id) = ''")
    cur.execute("ALTER TABLE audit_decisions ALTER COLUMN tenant_id SET NOT NULL")
    cur.execute("ALTER TABLE audit_overrides ALTER COLUMN tenant_id SET NOT NULL")
    cur.execute("ALTER TABLE audit_checkpoints ALTER COLUMN tenant_id SET NOT NULL")
    cur.execute("ALTER TABLE audit_proof_packs ALTER COLUMN tenant_id SET NOT NULL")
    cur.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'audit_decisions_pkey'
                  AND conrelid = 'audit_decisions'::regclass
            ) THEN
                ALTER TABLE audit_decisions DROP CONSTRAINT audit_decisions_pkey;
            END IF;
            ALTER TABLE audit_decisions ADD CONSTRAINT audit_decisions_pkey PRIMARY KEY (tenant_id, decision_id);
        EXCEPTION
            WHEN duplicate_table THEN NULL;
            WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'audit_overrides_pkey'
                  AND conrelid = 'audit_overrides'::regclass
            ) THEN
                ALTER TABLE audit_overrides DROP CONSTRAINT audit_overrides_pkey;
            END IF;
            ALTER TABLE audit_overrides ADD CONSTRAINT audit_overrides_pkey PRIMARY KEY (tenant_id, override_id);
        EXCEPTION
            WHEN duplicate_table THEN NULL;
            WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'audit_checkpoints_pkey'
                  AND conrelid = 'audit_checkpoints'::regclass
            ) THEN
                ALTER TABLE audit_checkpoints DROP CONSTRAINT audit_checkpoints_pkey;
            END IF;
            ALTER TABLE audit_checkpoints ADD CONSTRAINT audit_checkpoints_pkey PRIMARY KEY (tenant_id, checkpoint_id);
        EXCEPTION
            WHEN duplicate_table THEN NULL;
            WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'audit_proof_packs_pkey'
                  AND conrelid = 'audit_proof_packs'::regclass
            ) THEN
                ALTER TABLE audit_proof_packs DROP CONSTRAINT audit_proof_packs_pkey;
            END IF;
            ALTER TABLE audit_proof_packs ADD CONSTRAINT audit_proof_packs_pkey PRIMARY KEY (tenant_id, proof_pack_id);
        EXCEPTION
            WHEN duplicate_table THEN NULL;
            WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    now = datetime.now(timezone.utc)
    for migration in MIGRATIONS:
        cur.execute(
            """
            INSERT INTO schema_migrations (migration_id, description, applied_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (migration_id) DO NOTHING
            """,
            (migration.migration_id, migration.description, now),
        )
    latest = MIGRATIONS[-1].migration_id if MIGRATIONS else SCHEMA_VERSION
    cur.execute(
        """
        INSERT INTO schema_state (id, current_version, migration_id, updated_at)
        VALUES (1, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET
            current_version = EXCLUDED.current_version,
            migration_id = EXCLUDED.migration_id,
            updated_at = EXCLUDED.updated_at
        """,
        (latest, latest, now),
    )
    conn.commit()
    conn.close()
    return SCHEMA_VERSION


def init_db() -> str:
    """
    Initialize SQLite schema and apply forward-only migrations.
    Returns current schema version identifier.
    """
    backend = (os.getenv("RELEASEGATE_STORAGE_BACKEND") or "sqlite").strip().lower()
    if backend == "postgres":
        return _init_postgres_schema()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # System-scoped operational telemetry/cache tables (non-tenant governance data).
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS pr_runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo TEXT NOT NULL,
            pr_number INTEGER NOT NULL,
            base_sha TEXT,
            head_sha TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            risk_probability FLOAT,
            feature_version TEXT DEFAULT 'v1',
            files_touched INTEGER DEFAULT 0,
            files_json TEXT,
            churn INTEGER DEFAULT 0,
            entropy FLOAT DEFAULT 0.0,
            critical_files_count INTEGER DEFAULT 0,
            criticality_tier INTEGER DEFAULT 0,
            blast_radius INTEGER DEFAULT 0,
            hotspot_score FLOAT DEFAULT 0.0,
            label_value INTEGER,
            label_source TEXT,
            label_confidence FLOAT,
            label_tags TEXT,
            label_reason TEXT,
            label_sources TEXT,
            label_updated_at TIMESTAMP,
            label_version TEXT,
            entity_type TEXT DEFAULT 'commit',
            entity_id TEXT,
            linked_pr TEXT,
            linked_issue_ids TEXT,
            reasons_json TEXT,
            features_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            github_run_id TEXT,
            github_run_attempt TEXT,
            schema_version INTEGER DEFAULT 3,
            UNIQUE(repo, pr_number, head_sha)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS pr_labels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo TEXT NOT NULL,
            pr_number INTEGER NOT NULL,
            label_type TEXT NOT NULL,
            severity INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(repo, pr_number, label_type)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS github_cache (
            cache_key TEXT PRIMARY KEY,
            response_json TEXT,
            etag TEXT,
            fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS gitlab_cache (
            cache_key TEXT PRIMARY KEY,
            response_json TEXT,
            fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS repo_baselines (
            repo TEXT NOT NULL,
            feature_version TEXT NOT NULL,
            log_churn_mean FLOAT,
            log_churn_std FLOAT,
            files_changed_p50 FLOAT,
            files_changed_p90 FLOAT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (repo, feature_version)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS file_stats (
            repo TEXT NOT NULL,
            feature_version TEXT NOT NULL,
            file_path TEXT NOT NULL,
            total_changes INTEGER DEFAULT 0,
            incident_changes INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (repo, feature_version, file_path)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS bucket_stats (
            repo TEXT NOT NULL,
            feature_version TEXT NOT NULL,
            bucket_id TEXT NOT NULL,
            total_count INTEGER DEFAULT 0,
            incident_count INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (repo, feature_version, bucket_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS enforcement_events (
            idempotency_key TEXT PRIMARY KEY,
            decision_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            detail TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_decisions (
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
            created_at TIMESTAMP NOT NULL,
            evaluation_key TEXT,
            PRIMARY KEY (tenant_id, decision_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_overrides (
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
            created_at TIMESTAMP NOT NULL,
            PRIMARY KEY (tenant_id, override_id)
        )
        """
    )

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
        CREATE TABLE IF NOT EXISTS audit_checkpoints (
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
        CREATE TABLE IF NOT EXISTS audit_proof_packs (
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

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_context_id ON audit_decisions(context_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant_repo_created ON audit_decisions(tenant_id, repo, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant_repo_pr ON audit_decisions(tenant_id, repo, pr_number, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant_status_created ON audit_decisions(tenant_id, release_status, created_at)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_tenant_evaluation_key ON audit_decisions(tenant_id, evaluation_key)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_decisions_tenant_decision ON audit_decisions(tenant_id, decision_id)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_overrides_tenant_repo_created ON audit_overrides(tenant_id, repo, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_overrides_tenant_repo_pr ON audit_overrides(tenant_id, repo, pr_number, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_overrides_tenant_target_created ON audit_overrides(tenant_id, target_type, target_id, created_at)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_overrides_tenant_idempotency_key ON audit_overrides(tenant_id, idempotency_key)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_overrides_tenant_override ON audit_overrides(tenant_id, override_id)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_snapshots_tenant_decision ON policy_snapshots(tenant_id, decision_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_bundles_tenant_active_created ON policy_bundles(tenant_id, is_active, created_at)")
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_checkpoint_tenant_scope ON audit_checkpoints(tenant_id, repo, cadence, period_id, pr_number)"
    )
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_checkpoints_tenant_checkpoint ON audit_checkpoints(tenant_id, checkpoint_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_proof_packs_tenant_decision ON audit_proof_packs(tenant_id, decision_id, created_at)"
    )
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_proof_packs_tenant_proof_pack ON audit_proof_packs(tenant_id, proof_pack_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_metrics_events_tenant_metric_time ON metrics_events(tenant_id, metric_name, created_at)"
    )

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

    conn.commit()
    auto_migrate = (os.getenv("RELEASEGATE_AUTO_MIGRATE", "true").strip().lower() in {"1", "true", "yes", "on"})
    current_version = apply_sqlite_migrations(conn, auto_apply=auto_migrate)
    conn.close()
    return current_version
