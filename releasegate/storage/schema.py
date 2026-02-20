from __future__ import annotations

from datetime import datetime, timezone
import os
import sqlite3

from releasegate.config import DB_PATH
from releasegate.storage.migrations import MIGRATIONS, apply_sqlite_migrations


SCHEMA_VERSION = "v6"


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
            input_hash TEXT,
            policy_hash TEXT,
            replay_hash TEXT,
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
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_context_id ON audit_decisions(context_id)")
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_tenant_repo_created
        ON audit_decisions(tenant_id, repo, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_tenant_repo_pr
        ON audit_decisions(tenant_id, repo, pr_number, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_tenant_status_created
        ON audit_decisions(tenant_id, release_status, created_at DESC)
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
            ttl_seconds INTEGER,
            expires_at TIMESTAMPTZ,
            requested_by TEXT,
            approved_by TEXT,
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
        CREATE INDEX IF NOT EXISTS idx_overrides_tenant_repo_created
        ON audit_overrides(tenant_id, repo, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_overrides_tenant_repo_pr
        ON audit_overrides(tenant_id, repo, pr_number, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_overrides_tenant_expires_at
        ON audit_overrides(tenant_id, expires_at)
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_overrides_chain_prev
        ON audit_overrides(tenant_id, repo, previous_hash)
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_decision_refs (
            tenant_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            repo TEXT NOT NULL,
            pr_number INTEGER,
            ref_type TEXT NOT NULL,
            ref_value TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, decision_id, ref_type, ref_value)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_decision_refs_tenant_ref_created
        ON audit_decision_refs(tenant_id, ref_type, ref_value, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_decision_refs_tenant_repo_pr_created
        ON audit_decision_refs(tenant_id, repo, pr_number, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_audit_decision_refs_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Decision reference index is append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_audit_decision_refs_update'
            ) THEN
                CREATE TRIGGER prevent_audit_decision_refs_update
                BEFORE UPDATE ON audit_decision_refs
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_audit_decision_refs_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_audit_decision_refs_delete'
            ) THEN
                CREATE TRIGGER prevent_audit_decision_refs_delete
                BEFORE DELETE ON audit_decision_refs
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_audit_decision_refs_mutation();
            END IF;
        END $$;
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
        CREATE TABLE IF NOT EXISTS audit_lock_checkpoints (
            tenant_id TEXT NOT NULL,
            checkpoint_id TEXT NOT NULL,
            chain_id TEXT NOT NULL,
            cadence TEXT NOT NULL,
            period_id TEXT NOT NULL,
            period_end TIMESTAMPTZ NOT NULL,
            head_seq INTEGER NOT NULL,
            head_hash TEXT NOT NULL,
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
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_lock_checkpoints_scope
        ON audit_lock_checkpoints(tenant_id, chain_id, cadence, period_id)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_lock_checkpoints_tenant_chain_created
        ON audit_lock_checkpoints(tenant_id, chain_id, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_lock_checkpoint_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Lock checkpoints are append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_lock_checkpoints_update'
            ) THEN
                CREATE TRIGGER prevent_lock_checkpoints_update
                BEFORE UPDATE ON audit_lock_checkpoints
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_lock_checkpoint_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_lock_checkpoints_delete'
            ) THEN
                CREATE TRIGGER prevent_lock_checkpoints_delete
                BEFORE DELETE ON audit_lock_checkpoints
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_lock_checkpoint_mutation();
            END IF;
        END $$;
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
        CREATE TABLE IF NOT EXISTS audit_attestations (
            tenant_id TEXT NOT NULL,
            attestation_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            repo TEXT,
            pr_number INTEGER,
            schema_version TEXT NOT NULL,
            key_id TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            signed_payload_hash TEXT NOT NULL,
            attestation_json JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, attestation_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_attestations_tenant_decision
        ON audit_attestations(tenant_id, decision_id)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_attestation_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Attestation log is append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_attestations_update'
            ) THEN
                CREATE TRIGGER prevent_attestations_update
                BEFORE UPDATE ON audit_attestations
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_attestation_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_attestations_delete'
            ) THEN
                CREATE TRIGGER prevent_attestations_delete
                BEFORE DELETE ON audit_attestations
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_attestation_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_transparency_log (
            tenant_id TEXT NOT NULL,
            attestation_id TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            repo TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            pr_number INTEGER,
            engine_git_sha TEXT,
            engine_version TEXT,
            issued_at TIMESTAMPTZ NOT NULL,
            inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (tenant_id, attestation_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_transparency_attestation_id
        ON audit_transparency_log(attestation_id)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transparency_repo_commit
        ON audit_transparency_log(repo, commit_sha)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transparency_issued_at_desc
        ON audit_transparency_log(issued_at DESC)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_transparency_roots (
            tenant_id TEXT NOT NULL,
            date_utc TEXT NOT NULL,
            leaf_count INTEGER NOT NULL,
            root_hash TEXT NOT NULL,
            computed_at TIMESTAMPTZ NOT NULL,
            engine_build_git_sha TEXT,
            engine_version TEXT,
            PRIMARY KEY (tenant_id, date_utc)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transparency_roots_computed_at_desc
        ON audit_transparency_roots(computed_at DESC)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_transparency_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Transparency log is append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_transparency_roots_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Transparency roots are append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_transparency_update'
            ) THEN
                CREATE TRIGGER prevent_transparency_update
                BEFORE UPDATE ON audit_transparency_log
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_transparency_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_transparency_roots_update'
            ) THEN
                CREATE TRIGGER prevent_transparency_roots_update
                BEFORE UPDATE ON audit_transparency_roots
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_transparency_roots_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_transparency_roots_delete'
            ) THEN
                CREATE TRIGGER prevent_transparency_roots_delete
                BEFORE DELETE ON audit_transparency_roots
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_transparency_roots_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_transparency_delete'
            ) THEN
                CREATE TRIGGER prevent_transparency_delete
                BEFORE DELETE ON audit_transparency_log
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_transparency_mutation();
            END IF;
        END $$;
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jira_lock_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            issue_key TEXT NOT NULL,
            event_type TEXT NOT NULL,
            decision_id TEXT,
            repo TEXT,
            pr_number INTEGER,
            reason_codes_json TEXT NOT NULL,
            policy_hash TEXT,
            policy_resolution_hash TEXT,
            override_expires_at TIMESTAMPTZ,
            override_reason TEXT,
            actor TEXT,
            chain_id TEXT,
            seq INTEGER,
            prev_hash TEXT,
            event_hash TEXT,
            ttl_seconds INTEGER,
            expires_at TIMESTAMPTZ,
            justification TEXT,
            context_json JSONB,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    cur.execute("ALTER TABLE jira_lock_events ADD COLUMN IF NOT EXISTS chain_id TEXT")
    cur.execute("ALTER TABLE jira_lock_events ADD COLUMN IF NOT EXISTS seq INTEGER")
    cur.execute("ALTER TABLE jira_lock_events ADD COLUMN IF NOT EXISTS prev_hash TEXT")
    cur.execute("ALTER TABLE jira_lock_events ADD COLUMN IF NOT EXISTS event_hash TEXT")
    cur.execute("ALTER TABLE jira_lock_events ADD COLUMN IF NOT EXISTS ttl_seconds INTEGER")
    cur.execute("ALTER TABLE jira_lock_events ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ")
    cur.execute("ALTER TABLE jira_lock_events ADD COLUMN IF NOT EXISTS justification TEXT")
    cur.execute("ALTER TABLE jira_lock_events ADD COLUMN IF NOT EXISTS context_json JSONB")
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_jira_lock_events_tenant_issue_created
        ON jira_lock_events(tenant_id, issue_key, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_jira_lock_events_tenant_created
        ON jira_lock_events(tenant_id, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_jira_lock_events_tenant_chain_seq
        ON jira_lock_events(tenant_id, chain_id, seq DESC)
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_jira_lock_events_tenant_chain_seq
        ON jira_lock_events(tenant_id, chain_id, seq)
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_jira_lock_events_tenant_chain_prev_hash
        ON jira_lock_events(tenant_id, chain_id, prev_hash)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_jira_lock_event_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Jira lock ledger is append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_jira_lock_events_update'
            ) THEN
                CREATE TRIGGER prevent_jira_lock_events_update
                BEFORE UPDATE ON jira_lock_events
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_jira_lock_event_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_jira_lock_events_delete'
            ) THEN
                CREATE TRIGGER prevent_jira_lock_events_delete
                BEFORE DELETE ON jira_lock_events
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_jira_lock_event_mutation();
            END IF;
        END $$;
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jira_issue_locks_current (
            tenant_id TEXT NOT NULL,
            issue_key TEXT NOT NULL,
            locked BOOLEAN NOT NULL,
            lock_reason_codes_json TEXT NOT NULL,
            policy_hash TEXT,
            policy_resolution_hash TEXT,
            decision_id TEXT,
            repo TEXT,
            pr_number INTEGER,
            locked_by TEXT,
            override_expires_at TIMESTAMPTZ,
            override_reason TEXT,
            override_by TEXT,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, issue_key)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_jira_issue_locks_current_tenant_locked
        ON jira_issue_locks_current(tenant_id, locked, updated_at DESC)
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
        CREATE TABLE IF NOT EXISTS policy_resolved_snapshots (
            tenant_id TEXT NOT NULL,
            snapshot_id TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            snapshot_json JSONB NOT NULL,
            schema_version TEXT NOT NULL,
            compiler_version TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, snapshot_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_resolved_snapshots_tenant_hash
        ON policy_resolved_snapshots(tenant_id, policy_hash)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_resolved_snapshots_tenant_created
        ON policy_resolved_snapshots(tenant_id, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS governance_override_metrics_daily (
            tenant_id TEXT NOT NULL,
            date_utc TEXT NOT NULL,
            chain_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            overrides_total INTEGER NOT NULL,
            locks_total INTEGER NOT NULL,
            unlocks_total INTEGER NOT NULL,
            override_expires_total INTEGER NOT NULL,
            high_risk_overrides_total INTEGER NOT NULL,
            distinct_issues_total INTEGER NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, date_utc, chain_id, actor)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_override_metrics_daily_tenant_date
        ON governance_override_metrics_daily(tenant_id, date_utc)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_override_metrics_daily_tenant_actor
        ON governance_override_metrics_daily(tenant_id, actor, date_utc DESC)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_decision_records (
            tenant_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            issue_key TEXT,
            transition_id TEXT,
            actor_id TEXT,
            snapshot_id TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason_codes_json JSONB NOT NULL,
            signal_bundle_hash TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, decision_id)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_decision_records_tenant_snapshot
        ON policy_decision_records(tenant_id, snapshot_id, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_releases (
            tenant_id TEXT NOT NULL,
            release_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            snapshot_id TEXT NOT NULL,
            target_env TEXT NOT NULL,
            state TEXT NOT NULL,
            effective_at TIMESTAMPTZ,
            activated_at TIMESTAMPTZ,
            created_by TEXT,
            change_ticket TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, release_id)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_releases_tenant_scope_state
        ON policy_releases(tenant_id, policy_id, target_env, state, effective_at, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS active_policy_pointers (
            tenant_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            target_env TEXT NOT NULL,
            active_release_id TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, policy_id, target_env)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_release_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            release_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor_id TEXT,
            metadata_json JSONB,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_release_events_tenant_release_created
        ON policy_release_events(tenant_id, release_id, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_registry_entries (
            tenant_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            scope_type TEXT NOT NULL,
            scope_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            status TEXT NOT NULL,
            policy_json JSONB NOT NULL,
            policy_hash TEXT NOT NULL,
            lint_errors_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            lint_warnings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            rollout_percentage INTEGER NOT NULL DEFAULT 100,
            rollout_scope TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            created_by TEXT,
            activated_at TIMESTAMPTZ,
            activated_by TEXT,
            supersedes_policy_id TEXT,
            PRIMARY KEY (tenant_id, policy_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_registry_scope_version
        ON policy_registry_entries(tenant_id, scope_type, scope_id, version)
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_registry_active_scope
        ON policy_registry_entries(tenant_id, scope_type, scope_id)
        WHERE status = 'ACTIVE'
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_registry_scope_status_created
        ON policy_registry_entries(tenant_id, scope_type, scope_id, status, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_policy_registry_hash
        ON policy_registry_entries(tenant_id, policy_hash, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_policy_registry_payload_mutation()
        RETURNS trigger AS $$
        BEGIN
            IF
                NEW.scope_type IS DISTINCT FROM OLD.scope_type OR
                NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
                NEW.version IS DISTINCT FROM OLD.version OR
                NEW.policy_json IS DISTINCT FROM OLD.policy_json OR
                NEW.policy_hash IS DISTINCT FROM OLD.policy_hash OR
                NEW.lint_errors_json IS DISTINCT FROM OLD.lint_errors_json OR
                NEW.lint_warnings_json IS DISTINCT FROM OLD.lint_warnings_json OR
                NEW.rollout_percentage IS DISTINCT FROM OLD.rollout_percentage OR
                NEW.rollout_scope IS DISTINCT FROM OLD.rollout_scope OR
                NEW.created_at IS DISTINCT FROM OLD.created_at OR
                NEW.created_by IS DISTINCT FROM OLD.created_by
            THEN
                RAISE EXCEPTION 'Policy registry payload is immutable: create a new version instead';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_policy_registry_payload_mutation'
            ) THEN
                CREATE TRIGGER prevent_policy_registry_payload_mutation
                BEFORE UPDATE ON policy_registry_entries
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_policy_registry_payload_mutation();
            END IF;
        END $$;
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
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_decision_replays (
            tenant_id TEXT NOT NULL,
            replay_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            match BOOLEAN NOT NULL,
            status TEXT NOT NULL DEFAULT 'COMPLETED',
            diff_json JSONB NOT NULL,
            old_output_hash TEXT,
            new_output_hash TEXT,
            old_policy_hash TEXT,
            new_policy_hash TEXT,
            old_input_hash TEXT,
            new_input_hash TEXT,
            ran_engine_version TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, replay_id)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_decision_replays_tenant_decision_created
        ON audit_decision_replays(tenant_id, decision_id, created_at DESC)
        """
    )
    cur.execute("ALTER TABLE audit_decision_replays ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'COMPLETED'")
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_decision_replays_tenant_status_created
        ON audit_decision_replays(tenant_id, status, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_decision_replay_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Decision replay ledger is append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_decision_replays_update'
            ) THEN
                CREATE TRIGGER prevent_decision_replays_update
                BEFORE UPDATE ON audit_decision_replays
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_decision_replay_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_decision_replays_delete'
            ) THEN
                CREATE TRIGGER prevent_decision_replays_delete
                BEFORE DELETE ON audit_decision_replays
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_decision_replay_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_nodes (
            tenant_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            type TEXT NOT NULL,
            ref TEXT NOT NULL,
            hash TEXT,
            payload_json JSONB,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, node_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_nodes_tenant_type_ref
        ON evidence_nodes(tenant_id, type, ref)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_evidence_nodes_tenant_type_created
        ON evidence_nodes(tenant_id, type, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_evidence_node_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Evidence nodes are append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_evidence_nodes_update'
            ) THEN
                CREATE TRIGGER prevent_evidence_nodes_update
                BEFORE UPDATE ON evidence_nodes
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_evidence_node_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_evidence_nodes_delete'
            ) THEN
                CREATE TRIGGER prevent_evidence_nodes_delete
                BEFORE DELETE ON evidence_nodes
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_evidence_node_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_edges (
            tenant_id TEXT NOT NULL,
            edge_id TEXT NOT NULL,
            from_node_id TEXT NOT NULL,
            to_node_id TEXT NOT NULL,
            type TEXT NOT NULL,
            metadata_json JSONB,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, edge_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_edges_tenant_from_to_type
        ON evidence_edges(tenant_id, from_node_id, to_node_id, type)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_evidence_edges_tenant_from_created
        ON evidence_edges(tenant_id, from_node_id, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_evidence_edges_tenant_to_created
        ON evidence_edges(tenant_id, to_node_id, created_at DESC)
        """
    )
    cur.execute(
        """
        CREATE OR REPLACE FUNCTION releasegate_prevent_evidence_edge_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'Evidence edges are append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_evidence_edges_update'
            ) THEN
                CREATE TRIGGER prevent_evidence_edges_update
                BEFORE UPDATE ON evidence_edges
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_evidence_edge_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'prevent_evidence_edges_delete'
            ) THEN
                CREATE TRIGGER prevent_evidence_edges_delete
                BEFORE DELETE ON evidence_edges
                FOR EACH ROW
                EXECUTE FUNCTION releasegate_prevent_evidence_edge_mutation();
            END IF;
        END $$;
        """
    )
    cur.execute(
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
            roles_json JSONB NOT NULL,
            scopes_json JSONB NOT NULL,
            created_by TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            last_used_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ,
            is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            PRIMARY KEY (tenant_id, key_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_tenant_key_hash
        ON api_keys(tenant_id, key_hash)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_active
        ON api_keys(tenant_id, revoked_at, created_at)
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_global_key_id
        ON api_keys(key_id)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_nonces (
            tenant_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            signature_hash TEXT NOT NULL,
            used_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, integration_id, nonce)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_webhook_nonces_expires_at
        ON webhook_nonces(expires_at)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_signing_keys (
            tenant_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            encrypted_secret TEXT NOT NULL,
            secret_hash TEXT NOT NULL,
            created_by TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            rotated_at TIMESTAMPTZ,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            PRIMARY KEY (tenant_id, integration_id, key_id)
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_webhook_signing_keys_key_id
        ON webhook_signing_keys(key_id)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_webhook_signing_keys_tenant_integration_active
        ON webhook_signing_keys(tenant_id, integration_id, is_active, created_at)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS security_audit_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            auth_method TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            metadata_json JSONB,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_security_events_tenant_action_created
        ON security_audit_events(tenant_id, action, created_at)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS checkpoint_signing_keys (
            tenant_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            created_by TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            rotated_at TIMESTAMPTZ,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            PRIMARY KEY (tenant_id, key_id)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_checkpoint_keys_tenant_active_created
        ON checkpoint_signing_keys(tenant_id, is_active, created_at)
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS idempotency_keys (
            tenant_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            idem_key TEXT NOT NULL,
            request_fingerprint TEXT NOT NULL,
            status TEXT NOT NULL,
            response_json JSONB,
            resource_type TEXT,
            resource_id TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (tenant_id, operation, idem_key)
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_idempotency_keys_tenant_operation_created
        ON idempotency_keys(tenant_id, operation, created_at)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires_at
        ON idempotency_keys(expires_at)
        """
    )
    # Ensure existing Postgres deployments are hardened to tenant-scoped PKs.
    cur.execute("ALTER TABLE audit_decisions ADD COLUMN IF NOT EXISTS tenant_id TEXT")
    cur.execute("ALTER TABLE audit_overrides ADD COLUMN IF NOT EXISTS tenant_id TEXT")
    cur.execute("ALTER TABLE audit_overrides ADD COLUMN IF NOT EXISTS ttl_seconds INTEGER")
    cur.execute("ALTER TABLE audit_overrides ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ")
    cur.execute("ALTER TABLE audit_overrides ADD COLUMN IF NOT EXISTS requested_by TEXT")
    cur.execute("ALTER TABLE audit_overrides ADD COLUMN IF NOT EXISTS approved_by TEXT")
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
    cur.execute("ALTER TABLE audit_decisions ADD COLUMN IF NOT EXISTS input_hash TEXT")
    cur.execute("ALTER TABLE audit_decisions ADD COLUMN IF NOT EXISTS policy_hash TEXT")
    cur.execute("ALTER TABLE audit_decisions ADD COLUMN IF NOT EXISTS replay_hash TEXT")
    cur.execute("ALTER TABLE audit_transparency_log ADD COLUMN IF NOT EXISTS engine_git_sha TEXT")
    cur.execute("ALTER TABLE audit_transparency_log ADD COLUMN IF NOT EXISTS engine_version TEXT")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_transparency_roots (
            tenant_id TEXT NOT NULL,
            date_utc TEXT NOT NULL,
            leaf_count INTEGER NOT NULL,
            root_hash TEXT NOT NULL,
            computed_at TIMESTAMPTZ NOT NULL,
            engine_build_git_sha TEXT,
            engine_version TEXT,
            PRIMARY KEY (tenant_id, date_utc)
        )
        """
    )
    cur.execute("ALTER TABLE audit_transparency_roots ADD COLUMN IF NOT EXISTS engine_build_git_sha TEXT")
    cur.execute("ALTER TABLE audit_transparency_roots ADD COLUMN IF NOT EXISTS engine_version TEXT")
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transparency_roots_computed_at_desc
        ON audit_transparency_roots(computed_at DESC)
        """
    )
    cur.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_algorithm TEXT")
    cur.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_iterations INTEGER")
    cur.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_salt TEXT")
    cur.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS is_enabled BOOLEAN")
    cur.execute("UPDATE api_keys SET key_algorithm = COALESCE(NULLIF(btrim(key_algorithm), ''), 'legacy_sha256')")
    cur.execute("UPDATE api_keys SET key_iterations = COALESCE(key_iterations, 0)")
    cur.execute("UPDATE api_keys SET key_salt = COALESCE(key_salt, '')")
    cur.execute("UPDATE api_keys SET is_enabled = COALESCE(is_enabled, CASE WHEN revoked_at IS NULL THEN TRUE ELSE FALSE END)")
    cur.execute("ALTER TABLE api_keys ALTER COLUMN is_enabled SET DEFAULT TRUE")
    cur.execute("ALTER TABLE api_keys ALTER COLUMN is_enabled SET NOT NULL")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_global_key_id ON api_keys(key_id)")
    cur.execute("ALTER TABLE webhook_nonces ADD COLUMN IF NOT EXISTS integration_id TEXT")
    cur.execute("ALTER TABLE webhook_nonces ADD COLUMN IF NOT EXISTS key_id TEXT")
    cur.execute(
        "UPDATE webhook_nonces SET integration_id = COALESCE(NULLIF(btrim(integration_id), ''), 'legacy')"
    )
    cur.execute("UPDATE webhook_nonces SET key_id = COALESCE(NULLIF(btrim(key_id), ''), 'legacy')")
    cur.execute("ALTER TABLE webhook_nonces ALTER COLUMN integration_id SET NOT NULL")
    cur.execute("ALTER TABLE webhook_nonces ALTER COLUMN key_id SET NOT NULL")
    cur.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'webhook_nonces_pkey'
                  AND conrelid = 'webhook_nonces'::regclass
            ) THEN
                ALTER TABLE webhook_nonces DROP CONSTRAINT webhook_nonces_pkey;
            END IF;
            ALTER TABLE webhook_nonces ADD CONSTRAINT webhook_nonces_pkey PRIMARY KEY (tenant_id, integration_id, nonce);
        EXCEPTION
            WHEN duplicate_table THEN NULL;
            WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_overrides_chain_prev
        ON audit_overrides(tenant_id, repo, previous_hash)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_overrides_tenant_expires_at
        ON audit_overrides(tenant_id, expires_at)
        """
    )
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
    # If we're already inside an active storage transaction, schema bootstrap has
    # already happened on entry. Re-initializing via a separate connection can
    # deadlock (notably on SQLite BEGIN IMMEDIATE), so short-circuit.
    try:
        from releasegate.storage import get_storage_backend as _get_storage_backend

        active_backend = _get_storage_backend()
        active_getter = getattr(active_backend, "_active_tx", None)
        if callable(active_getter):
            tx_state = active_getter()
            if tx_state is not None:
                return SCHEMA_VERSION
    except Exception:
        # Fallback to normal init path.
        pass

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
            input_hash TEXT,
            policy_hash TEXT,
            replay_hash TEXT,
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
            ttl_seconds INTEGER,
            expires_at TEXT,
            requested_by TEXT,
            approved_by TEXT,
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
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_overrides_chain_prev ON audit_overrides(tenant_id, repo, previous_hash)")

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
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_tenant_key_hash ON api_keys(tenant_id, key_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_active ON api_keys(tenant_id, revoked_at, created_at)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_global_key_id ON api_keys(key_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_nonces_expires_at ON webhook_nonces(expires_at)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_webhook_signing_keys_key_id ON webhook_signing_keys(key_id)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_webhook_signing_keys_tenant_integration_active ON webhook_signing_keys(tenant_id, integration_id, is_active, created_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_events_tenant_action_created ON security_audit_events(tenant_id, action, created_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_idempotency_keys_tenant_operation_created ON idempotency_keys(tenant_id, operation, created_at)"
    )
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires_at ON idempotency_keys(expires_at)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_checkpoint_keys_tenant_active_created ON checkpoint_signing_keys(tenant_id, is_active, created_at)"
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
