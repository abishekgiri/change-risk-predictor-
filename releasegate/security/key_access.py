from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _ensure_key_access_log_table() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS key_access_log (
            tenant_id TEXT NOT NULL,
            access_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            actor TEXT,
            purpose TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, access_id)
        )
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_key_access_log_tenant_key_created
        ON key_access_log(tenant_id, key_id, created_at DESC)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_key_access_log_tenant_operation_created
        ON key_access_log(tenant_id, operation, created_at DESC)
        """
    )

    if storage.name == "postgres":
        storage.execute(
            """
            CREATE OR REPLACE FUNCTION releasegate_prevent_key_access_log_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'Key access log is append-only: % not allowed', TG_OP;
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
                    WHERE tgname = 'prevent_key_access_log_update'
                ) THEN
                    CREATE TRIGGER prevent_key_access_log_update
                    BEFORE UPDATE ON key_access_log
                    FOR EACH ROW
                    EXECUTE FUNCTION releasegate_prevent_key_access_log_mutation();
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
                    WHERE tgname = 'prevent_key_access_log_delete'
                ) THEN
                    CREATE TRIGGER prevent_key_access_log_delete
                    BEFORE DELETE ON key_access_log
                    FOR EACH ROW
                    EXECUTE FUNCTION releasegate_prevent_key_access_log_mutation();
                END IF;
            END $$;
            """
        )
    else:
        storage.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_key_access_log_update
            BEFORE UPDATE ON key_access_log
            BEGIN
                SELECT RAISE(FAIL, 'Key access log is append-only: UPDATE not allowed');
            END;
            """
        )
        storage.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_key_access_log_delete
            BEFORE DELETE ON key_access_log
            BEGIN
                SELECT RAISE(FAIL, 'Key access log is append-only: DELETE not allowed');
            END;
            """
        )


def log_key_access(
    *,
    tenant_id: str,
    key_id: str,
    operation: str,
    actor: Optional[str] = None,
    purpose: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    init_db()
    _ensure_key_access_log_table()
    storage = get_storage_backend()
    access_id = uuid.uuid4().hex
    storage.execute(
        """
        INSERT INTO key_access_log (
            tenant_id, access_id, key_id, operation, actor, purpose, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            resolve_tenant_id(tenant_id),
            access_id,
            str(key_id or "").strip(),
            str(operation or "").strip().lower(),
            str(actor or "").strip() or None,
            str(purpose or "").strip() or None,
            json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    return access_id


def list_key_access_logs(
    *,
    tenant_id: str,
    key_id: Optional[str] = None,
    operation: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    init_db()
    _ensure_key_access_log_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    effective_limit = max(1, min(int(limit), 500))
    query = """
        SELECT tenant_id, access_id, key_id, operation, actor, purpose, metadata_json, created_at
        FROM key_access_log
        WHERE tenant_id = ?
    """
    params: List[Any] = [effective_tenant]
    if key_id:
        query += " AND key_id = ?"
        params.append(str(key_id).strip())
    if operation:
        query += " AND operation = ?"
        params.append(str(operation).strip().lower())
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(effective_limit)
    rows = storage.fetchall(query, tuple(params))
    for row in rows:
        raw = row.get("metadata_json")
        if isinstance(raw, str):
            try:
                row["metadata"] = json.loads(raw)
            except Exception:
                row["metadata"] = {}
        elif isinstance(raw, dict):
            row["metadata"] = dict(raw)
        else:
            row["metadata"] = {}
    return rows

