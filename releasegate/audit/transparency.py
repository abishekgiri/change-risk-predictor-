from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


DEFAULT_LIMIT = 50
MAX_LIMIT = 500


def _ensure_audit_transparency_log_table() -> None:
    """
    Backward-compatible bootstrap for environments where the transparency
    migration has not been applied yet.
    """
    storage = get_storage_backend()
    storage.execute(
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
            issued_at TEXT NOT NULL,
            inserted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (tenant_id, attestation_id)
        )
        """
    )
    if storage.name == "postgres":
        storage.execute(
            """
            ALTER TABLE audit_transparency_log
            ADD COLUMN IF NOT EXISTS engine_git_sha TEXT
            """
        )
        storage.execute(
            """
            ALTER TABLE audit_transparency_log
            ADD COLUMN IF NOT EXISTS engine_version TEXT
            """
        )
    else:
        try:
            storage.execute("ALTER TABLE audit_transparency_log ADD COLUMN engine_git_sha TEXT")
        except Exception as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
        try:
            storage.execute("ALTER TABLE audit_transparency_log ADD COLUMN engine_version TEXT")
        except Exception as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
    storage.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_transparency_attestation_id
        ON audit_transparency_log(attestation_id)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transparency_repo_commit
        ON audit_transparency_log(repo, commit_sha)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transparency_issued_at_desc
        ON audit_transparency_log(issued_at DESC)
        """
    )
    if storage.name == "postgres":
        storage.execute(
            """
            CREATE OR REPLACE FUNCTION releasegate_prevent_transparency_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'Transparency log is append-only: % not allowed', TG_OP;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        storage.execute(
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
        storage.execute(
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
    else:
        storage.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_transparency_update
            BEFORE UPDATE ON audit_transparency_log
            BEGIN
                SELECT RAISE(FAIL, 'Transparency log is append-only: UPDATE not allowed');
            END;
            """
        )
        storage.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_transparency_delete
            BEFORE DELETE ON audit_transparency_log
            BEGIN
                SELECT RAISE(FAIL, 'Transparency log is append-only: DELETE not allowed');
            END;
            """
        )


def _normalize_limit(limit: int) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    if value <= 0:
        raise ValueError("limit must be greater than 0")
    return min(value, MAX_LIMIT)


def _row_to_item(row: Dict[str, Any]) -> Dict[str, Any]:
    git_sha = str(row.get("engine_git_sha") or "").strip() or None
    version = str(row.get("engine_version") or "").strip() or None
    return {
        "tenant_id": row.get("tenant_id"),
        "attestation_id": row.get("attestation_id"),
        "payload_hash": row.get("payload_hash"),
        "subject": {
            "repo": row.get("repo"),
            "commit_sha": row.get("commit_sha"),
            "pr_number": row.get("pr_number"),
        },
        "engine_build": {
            "git_sha": git_sha,
            "version": version,
        },
        "issued_at": row.get("issued_at"),
        "inserted_at": row.get("inserted_at"),
    }


def record_transparency_entry(
    *,
    tenant_id: str,
    attestation_id: str,
    payload_hash: str,
    repo: str,
    commit_sha: str,
    pr_number: Optional[int],
    issued_at: Optional[str],
    engine_git_sha: Optional[str],
    engine_version: Optional[str],
) -> None:
    init_db()
    _ensure_audit_transparency_log_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    effective_repo = str(repo or "").strip()
    effective_commit = str(commit_sha or "").strip()
    if not effective_repo:
        raise ValueError("repo is required for transparency log")
    if not effective_commit:
        raise ValueError("commit_sha is required for transparency log")
    effective_issued_at = str(issued_at or "").strip() or datetime.now(timezone.utc).isoformat()

    storage.execute(
        """
        INSERT INTO audit_transparency_log (
            tenant_id, attestation_id, payload_hash, repo, commit_sha, pr_number, engine_git_sha, engine_version, issued_at, inserted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, attestation_id) DO NOTHING
        """,
        (
            effective_tenant,
            str(attestation_id),
            str(payload_hash),
            effective_repo,
            effective_commit,
            pr_number,
            str(engine_git_sha or "").strip() or None,
            str(engine_version or "").strip() or None,
            effective_issued_at,
            datetime.now(timezone.utc).isoformat(),
        ),
    )


def record_transparency_for_attestation(
    *,
    tenant_id: str,
    attestation_id: str,
    fallback_repo: Optional[str],
    fallback_pr_number: Optional[int],
    payload_hash: str,
    attestation: Dict[str, Any],
) -> None:
    subject = attestation.get("subject") if isinstance(attestation, dict) else None
    subject = subject if isinstance(subject, dict) else {}
    repo = str(subject.get("repo") or fallback_repo or "")
    commit_sha = str(subject.get("commit_sha") or "")
    pr_number = subject.get("pr_number")
    if pr_number is None:
        pr_number = fallback_pr_number
    issued_at = str(attestation.get("issued_at") or "") if isinstance(attestation, dict) else ""
    engine_version = str(attestation.get("engine_version") or os.getenv("RELEASEGATE_VERSION") or "")
    engine_git_sha = str(
        os.getenv("RELEASEGATE_GIT_SHA")
        or os.getenv("RELEASEGATE_ENGINE_GIT_SHA")
        or ""
    )
    record_transparency_entry(
        tenant_id=tenant_id,
        attestation_id=attestation_id,
        payload_hash=payload_hash,
        repo=repo,
        commit_sha=commit_sha,
        pr_number=pr_number,
        issued_at=issued_at,
        engine_git_sha=engine_git_sha,
        engine_version=engine_version,
    )


def list_transparency_latest(*, limit: int = DEFAULT_LIMIT, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    init_db()
    _ensure_audit_transparency_log_table()
    storage = get_storage_backend()
    effective_limit = _normalize_limit(limit)

    if tenant_id is None:
        rows = storage.fetchall(
            """
            SELECT tenant_id, attestation_id, payload_hash, repo, commit_sha, pr_number, engine_git_sha, engine_version, issued_at, inserted_at
            FROM audit_transparency_log
            ORDER BY issued_at DESC, inserted_at DESC
            LIMIT ?
            """,
            (effective_limit,),
        )
    else:
        rows = storage.fetchall(
            """
            SELECT tenant_id, attestation_id, payload_hash, repo, commit_sha, pr_number, engine_git_sha, engine_version, issued_at, inserted_at
            FROM audit_transparency_log
            WHERE tenant_id = ?
            ORDER BY issued_at DESC, inserted_at DESC
            LIMIT ?
            """,
            (resolve_tenant_id(tenant_id), effective_limit),
        )

    return {
        "ok": True,
        "limit": effective_limit,
        "items": [_row_to_item(row) for row in rows],
    }


def get_transparency_entry(
    *,
    attestation_id: str,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_audit_transparency_log_table()
    storage = get_storage_backend()
    attestation_id = str(attestation_id or "").strip()
    if not attestation_id:
        raise ValueError("attestation_id is required")

    if tenant_id is None:
        row = storage.fetchone(
            """
            SELECT tenant_id, attestation_id, payload_hash, repo, commit_sha, pr_number, engine_git_sha, engine_version, issued_at, inserted_at
            FROM audit_transparency_log
            WHERE attestation_id = ?
            LIMIT 1
            """,
            (attestation_id,),
        )
    else:
        row = storage.fetchone(
            """
            SELECT tenant_id, attestation_id, payload_hash, repo, commit_sha, pr_number, engine_git_sha, engine_version, issued_at, inserted_at
            FROM audit_transparency_log
            WHERE tenant_id = ? AND attestation_id = ?
            LIMIT 1
            """,
            (resolve_tenant_id(tenant_id), attestation_id),
        )

    if not row:
        return None
    return _row_to_item(row)
