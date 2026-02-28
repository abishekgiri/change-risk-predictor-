from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography.fernet import Fernet

from releasegate.crypto.kms_client import (
    KMS_ENVELOPE_MODE,
    allow_legacy_key_material,
    kms_envelope_decrypt,
    kms_envelope_encrypt,
)
from releasegate.security.key_access import log_key_access
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _legacy_fernet() -> Fernet:
    raw = (os.getenv("RELEASEGATE_KEY_ENCRYPTION_SECRET") or "").strip()
    if raw:
        try:
            return Fernet(raw.encode("utf-8"))
        except Exception as exc:
            raise ValueError("Invalid RELEASEGATE_KEY_ENCRYPTION_SECRET provided") from exc

    # Fallback for local development ONLY. This is not secure for production.
    env = (os.getenv("RELEASEGATE_ENV") or "development").lower()
    if env not in {"dev", "development", "test"}:
        raise ValueError("RELEASEGATE_KEY_ENCRYPTION_SECRET must be set in production environments.")

    seed = (os.getenv("RELEASEGATE_JWT_SECRET") or "releasegate-local-dev").encode("utf-8")
    key = base64.urlsafe_b64encode(hashlib.sha256(seed).digest())
    return Fernet(key)


def _column_exists(table: str, column: str) -> bool:
    storage = get_storage_backend()
    if storage.name == "postgres":
        row = storage.fetchone(
            """
            SELECT 1 AS ok
            FROM information_schema.columns
            WHERE table_name = ? AND column_name = ?
            LIMIT 1
            """,
            (table, column),
        )
        return bool(row)
    rows = storage.fetchall(f"PRAGMA table_info({table})")
    return column in {str(row.get("name") or "") for row in rows}


def _ensure_column(table: str, column_sql: str) -> None:
    column_name = str(column_sql.split()[0]).strip()
    if _column_exists(table, column_name):
        return
    get_storage_backend().execute(f"ALTER TABLE {table} ADD COLUMN {column_sql}")


def _ensure_checkpoint_signing_keys_table() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS checkpoint_signing_keys (
            tenant_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            encrypted_data_key TEXT,
            kms_key_id TEXT,
            encryption_mode TEXT NOT NULL DEFAULT 'legacy_fernet',
            key_hash TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (tenant_id, key_id)
        )
        """
    )
    _ensure_column("checkpoint_signing_keys", "encrypted_data_key TEXT")
    _ensure_column("checkpoint_signing_keys", "kms_key_id TEXT")
    _ensure_column("checkpoint_signing_keys", "encryption_mode TEXT NOT NULL DEFAULT 'legacy_fernet'")
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_checkpoint_keys_tenant_active_created
        ON checkpoint_signing_keys(tenant_id, is_active, created_at)
        """
    )


def rotate_checkpoint_signing_key(
    *,
    tenant_id: str,
    raw_key: str,
    created_by: Optional[str],
    kms_key_id: Optional[str] = None,
) -> Dict[str, str]:
    init_db()
    _ensure_checkpoint_signing_keys_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now = datetime.now(timezone.utc).isoformat()
    key_id = uuid.uuid4().hex
    effective_kms_key_id = str(kms_key_id or os.getenv("RELEASEGATE_KMS_KEY_ID") or "").strip() or None
    envelope = kms_envelope_encrypt(
        raw_key.encode("utf-8"),
        kms_key_id=effective_kms_key_id,
        context={
            "tenant_id": effective_tenant,
            "key_id": key_id,
            "table": "checkpoint_signing_keys",
        },
    )
    encrypted = str(envelope.get("ciphertext") or "")
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    storage.execute(
        """
        UPDATE checkpoint_signing_keys
        SET is_active = ?, rotated_at = COALESCE(rotated_at, ?)
        WHERE tenant_id = ? AND is_active = ?
        """,
        (False, now, effective_tenant, True),
    )
    storage.execute(
        """
        INSERT INTO checkpoint_signing_keys (
            tenant_id, key_id, encrypted_key, encrypted_data_key, kms_key_id, encryption_mode, key_hash, created_by, created_at, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            key_id,
            encrypted,
            str(envelope.get("encrypted_data_key") or ""),
            effective_kms_key_id,
            str(envelope.get("encryption_mode") or KMS_ENVELOPE_MODE),
            key_hash,
            created_by,
            now,
            True,
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "key_id": key_id,
        "created_at": now,
    }


def get_active_checkpoint_signing_key(tenant_id: str) -> Optional[str]:
    record = get_active_checkpoint_signing_key_record(tenant_id)
    if not record:
        return None
    return record.get("key")


def _decrypt_checkpoint_key(
    *,
    tenant_id: str,
    key_id: str,
    encrypted_key: str,
    encrypted_data_key: Optional[str],
    kms_key_id: Optional[str],
    encryption_mode: Optional[str],
    operation: str,
    actor: Optional[str],
    purpose: Optional[str],
) -> str:
    mode = str(encryption_mode or "legacy_fernet").strip().lower()
    if mode == KMS_ENVELOPE_MODE:
        wrapped_data_key = str(encrypted_data_key or "").strip()
        if not wrapped_data_key:
            raise ValueError("missing encrypted_data_key for kms envelope checkpoint key")
        value = kms_envelope_decrypt(
            ciphertext=encrypted_key,
            encrypted_data_key=wrapped_data_key,
            kms_key_id=str(kms_key_id or "").strip() or None,
            context={
                "tenant_id": tenant_id,
                "key_id": key_id,
                "table": "checkpoint_signing_keys",
            },
        ).decode("utf-8")
    else:
        if not allow_legacy_key_material():
            raise ValueError("legacy checkpoint key decryption is disabled while RELEASEGATE_STRICT_KMS is enabled")
        value = _legacy_fernet().decrypt(encrypted_key.encode("utf-8")).decode("utf-8")
    log_key_access(
        tenant_id=tenant_id,
        key_id=key_id,
        operation=operation,
        actor=actor or "system",
        purpose=purpose or "checkpoint_signing_key_access",
        metadata={"encryption_mode": mode},
    )
    return value


def get_active_checkpoint_signing_key_record(
    tenant_id: str,
    *,
    operation: str = "decrypt",
    actor: Optional[str] = None,
    purpose: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    init_db()
    _ensure_checkpoint_signing_keys_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT key_id, encrypted_key, encrypted_data_key, kms_key_id, encryption_mode
        FROM checkpoint_signing_keys
        WHERE tenant_id = ? AND is_active = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (effective_tenant, True),
    )
    if not row:
        return None
    encrypted = str(row.get("encrypted_key") or "").strip()
    if not encrypted:
        return None
    return {
        "key_id": str(row.get("key_id") or ""),
        "key": _decrypt_checkpoint_key(
            tenant_id=effective_tenant,
            key_id=str(row.get("key_id") or ""),
            encrypted_key=encrypted,
            encrypted_data_key=row.get("encrypted_data_key"),
            kms_key_id=row.get("kms_key_id"),
            encryption_mode=row.get("encryption_mode"),
            operation=operation,
            actor=actor,
            purpose=purpose,
        ),
    }


def get_checkpoint_signing_key_record(
    tenant_id: str,
    key_id: str,
    *,
    operation: str = "decrypt",
    actor: Optional[str] = None,
    purpose: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    init_db()
    _ensure_checkpoint_signing_keys_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT key_id, encrypted_key, encrypted_data_key, kms_key_id, encryption_mode
        FROM checkpoint_signing_keys
        WHERE tenant_id = ? AND key_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(key_id)),
    )
    if not row:
        return None
    encrypted = str(row.get("encrypted_key") or "").strip()
    if not encrypted:
        return None
    return {
        "key_id": str(row.get("key_id") or ""),
        "key": _decrypt_checkpoint_key(
            tenant_id=effective_tenant,
            key_id=str(row.get("key_id") or ""),
            encrypted_key=encrypted,
            encrypted_data_key=row.get("encrypted_data_key"),
            kms_key_id=row.get("kms_key_id"),
            encryption_mode=row.get("encryption_mode"),
            operation=operation,
            actor=actor,
            purpose=purpose,
        ),
    }


def list_checkpoint_signing_keys(tenant_id: str) -> List[Dict[str, str]]:
    init_db()
    _ensure_checkpoint_signing_keys_table()
    storage = get_storage_backend()
    return storage.fetchall(
        """
        SELECT tenant_id, key_id, created_by, created_at, rotated_at, is_active
        FROM checkpoint_signing_keys
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        """,
        (resolve_tenant_id(tenant_id),),
    )
