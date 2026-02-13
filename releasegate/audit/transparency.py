from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional

from releasegate.attestation.merkle import (
    LEAF_VERSION,
    TREE_RULE,
    build_merkle_bundle,
    compute_transparency_leaf_hash,
    merkle_inclusion_proof,
)
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


def _ensure_audit_transparency_roots_table() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_transparency_roots (
            tenant_id TEXT NOT NULL,
            date_utc TEXT NOT NULL,
            leaf_count INTEGER NOT NULL,
            root_hash TEXT NOT NULL,
            computed_at TEXT NOT NULL,
            engine_build_git_sha TEXT,
            engine_version TEXT,
            PRIMARY KEY (tenant_id, date_utc)
        )
        """
    )
    if storage.name == "postgres":
        storage.execute(
            """
            ALTER TABLE audit_transparency_roots
            ADD COLUMN IF NOT EXISTS engine_build_git_sha TEXT
            """
        )
        storage.execute(
            """
            ALTER TABLE audit_transparency_roots
            ADD COLUMN IF NOT EXISTS engine_version TEXT
            """
        )
        storage.execute(
            """
            CREATE OR REPLACE FUNCTION releasegate_prevent_transparency_roots_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'Transparency roots are append-only: % not allowed', TG_OP;
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
        storage.execute(
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
    else:
        try:
            storage.execute("ALTER TABLE audit_transparency_roots ADD COLUMN engine_build_git_sha TEXT")
        except Exception as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
        try:
            storage.execute("ALTER TABLE audit_transparency_roots ADD COLUMN engine_version TEXT")
        except Exception as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
        storage.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_transparency_roots_update
            BEFORE UPDATE ON audit_transparency_roots
            BEGIN
                SELECT RAISE(FAIL, 'Transparency roots are append-only: UPDATE not allowed');
            END;
            """
        )
        storage.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_transparency_roots_delete
            BEFORE DELETE ON audit_transparency_roots
            BEGIN
                SELECT RAISE(FAIL, 'Transparency roots are append-only: DELETE not allowed');
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


def _normalize_date_utc(date_utc: str) -> str:
    value = str(date_utc or "").strip()
    if not value:
        raise ValueError("date is required in YYYY-MM-DD format")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("date must be in YYYY-MM-DD format") from exc
    return parsed.date().isoformat()


def _parse_issued_at_utc(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("issued_at is required")
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        # Fallback for DB-specific timestamp string formatting.
        if len(text) >= 10:
            dt = datetime.strptime(text[:10], "%Y-%m-%d")
        else:
            raise
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


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


def _root_row_to_item(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ok": True,
        "tenant_id": row.get("tenant_id"),
        "date_utc": row.get("date_utc"),
        "leaf_count": int(row.get("leaf_count") or 0),
        "root_hash": row.get("root_hash"),
        "computed_at": row.get("computed_at"),
        "engine_build": {
            "git_sha": str(row.get("engine_build_git_sha") or "").strip() or None,
            "version": str(row.get("engine_version") or "").strip() or None,
        },
    }


def _ordered_entries_for_date(*, tenant_id: str, date_utc: str) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    rows = storage.fetchall(
        """
        SELECT tenant_id, attestation_id, payload_hash, repo, commit_sha, pr_number,
               engine_git_sha, engine_version, issued_at, inserted_at
        FROM audit_transparency_log
        WHERE tenant_id = ?
        ORDER BY issued_at ASC, attestation_id ASC
        """,
        (tenant_id,),
    )

    filtered: List[Dict[str, Any]] = []
    for row in rows:
        issued_at_utc = _parse_issued_at_utc(row.get("issued_at"))
        if issued_at_utc.date().isoformat() == date_utc:
            filtered.append(dict(row))

    filtered.sort(
        key=lambda r: (
            _parse_issued_at_utc(r.get("issued_at")),
            str(r.get("attestation_id") or ""),
        )
    )
    return filtered


def _leaf_entry_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "leaf_version": LEAF_VERSION,
        "attestation_id": str(row.get("attestation_id") or ""),
        "payload_hash": str(row.get("payload_hash") or ""),
        "issued_at": str(row.get("issued_at") or ""),
        "repo": str(row.get("repo") or ""),
        "commit_sha": str(row.get("commit_sha") or ""),
        "pr_number": row.get("pr_number"),
    }


def _load_root_row(*, tenant_id: str, date_utc: str) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    return storage.fetchone(
        """
        SELECT tenant_id, date_utc, leaf_count, root_hash, computed_at, engine_build_git_sha, engine_version
        FROM audit_transparency_roots
        WHERE tenant_id = ? AND date_utc = ?
        LIMIT 1
        """,
        (tenant_id, date_utc),
    )


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


def get_or_compute_transparency_root(*, date_utc: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_audit_transparency_log_table()
    _ensure_audit_transparency_roots_table()
    storage = get_storage_backend()

    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_date = _normalize_date_utc(date_utc)

    existing = _load_root_row(tenant_id=effective_tenant, date_utc=normalized_date)
    if existing:
        return _root_row_to_item(existing)

    day_rows = _ordered_entries_for_date(tenant_id=effective_tenant, date_utc=normalized_date)
    if not day_rows:
        return None

    leaf_entries = [_leaf_entry_from_row(row) for row in day_rows]
    _, root_hash = build_merkle_bundle(leaf_entries)

    engine_git_sha = str(
        os.getenv("RELEASEGATE_GIT_SHA")
        or os.getenv("RELEASEGATE_ENGINE_GIT_SHA")
        or day_rows[-1].get("engine_git_sha")
        or ""
    ).strip() or None
    engine_version = str(
        os.getenv("RELEASEGATE_VERSION")
        or day_rows[-1].get("engine_version")
        or ""
    ).strip() or None

    storage.execute(
        """
        INSERT INTO audit_transparency_roots (
            tenant_id, date_utc, leaf_count, root_hash, computed_at, engine_build_git_sha, engine_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, date_utc) DO NOTHING
        """,
        (
            effective_tenant,
            normalized_date,
            len(day_rows),
            root_hash,
            datetime.now(timezone.utc).isoformat(),
            engine_git_sha,
            engine_version,
        ),
    )

    row = _load_root_row(tenant_id=effective_tenant, date_utc=normalized_date)
    if not row:
        return None
    return _root_row_to_item(row)


def get_transparency_inclusion_proof(
    *,
    attestation_id: str,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_audit_transparency_log_table()
    _ensure_audit_transparency_roots_table()
    storage = get_storage_backend()

    effective_tenant = resolve_tenant_id(tenant_id)
    att_id = str(attestation_id or "").strip()
    if not att_id:
        raise ValueError("attestation_id is required")

    row = storage.fetchone(
        """
        SELECT tenant_id, attestation_id, payload_hash, repo, commit_sha, pr_number,
               engine_git_sha, engine_version, issued_at, inserted_at
        FROM audit_transparency_log
        WHERE tenant_id = ? AND attestation_id = ?
        LIMIT 1
        """,
        (effective_tenant, att_id),
    )
    if not row:
        return None

    entry_date = _parse_issued_at_utc(row.get("issued_at")).date().isoformat()
    root_entry = get_or_compute_transparency_root(date_utc=entry_date, tenant_id=effective_tenant)
    if not root_entry:
        return None

    day_rows = _ordered_entries_for_date(tenant_id=effective_tenant, date_utc=entry_date)
    if int(root_entry.get("leaf_count") or 0) != len(day_rows):
        raise ValueError("anchored root leaf_count mismatch for date")

    leaf_entries = [_leaf_entry_from_row(item) for item in day_rows]
    leaf_hashes, computed_root = build_merkle_bundle(leaf_entries)
    if str(root_entry.get("root_hash") or "") != computed_root:
        raise ValueError("anchored root hash mismatch for date")

    index = -1
    for idx, item in enumerate(day_rows):
        if str(item.get("attestation_id") or "") == att_id:
            index = idx
            break
    if index < 0:
        return None

    proof = merkle_inclusion_proof(leaf_hashes, index)
    leaf_hash = compute_transparency_leaf_hash(leaf_entries[index])

    return {
        "ok": True,
        "tenant_id": effective_tenant,
        "attestation_id": att_id,
        "date_utc": entry_date,
        "leaf_hash": leaf_hash,
        "root_hash": computed_root,
        "index": index,
        "proof": proof,
        "leaf_version": LEAF_VERSION,
        "tree_rule": TREE_RULE,
    }
