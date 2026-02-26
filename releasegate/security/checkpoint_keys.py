from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography.fernet import Fernet

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _fernet() -> Fernet:
    raw = (os.getenv("RELEASEGATE_KEY_ENCRYPTION_SECRET") or "").strip()
    if raw:
        try:
            return Fernet(raw.encode("utf-8"))
        except Exception:
            pass
    seed = (raw or os.getenv("RELEASEGATE_JWT_SECRET") or "releasegate-local-dev").encode("utf-8")
    key = base64.urlsafe_b64encode(hashlib.sha256(seed).digest())
    return Fernet(key)


def rotate_checkpoint_signing_key(
    *,
    tenant_id: str,
    raw_key: str,
    created_by: Optional[str],
) -> Dict[str, str]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now = datetime.now(timezone.utc).isoformat()
    key_id = uuid.uuid4().hex
    encrypted = _fernet().encrypt(raw_key.encode("utf-8")).decode("utf-8")
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
            tenant_id, key_id, encrypted_key, key_hash, created_by, created_at, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            key_id,
            encrypted,
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


def get_active_checkpoint_signing_key_record(tenant_id: str) -> Optional[Dict[str, str]]:
    init_db()
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT key_id, encrypted_key
        FROM checkpoint_signing_keys
        WHERE tenant_id = ? AND is_active = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (resolve_tenant_id(tenant_id), True),
    )
    if not row:
        return None
    encrypted = row.get("encrypted_key")
    if not encrypted:
        return None
    return {
        "key_id": str(row.get("key_id") or ""),
        "key": _fernet().decrypt(encrypted.encode("utf-8")).decode("utf-8"),
    }


def get_checkpoint_signing_key_record(tenant_id: str, key_id: str) -> Optional[Dict[str, str]]:
    init_db()
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT key_id, encrypted_key
        FROM checkpoint_signing_keys
        WHERE tenant_id = ? AND key_id = ?
        LIMIT 1
        """,
        (resolve_tenant_id(tenant_id), str(key_id)),
    )
    if not row:
        return None
    encrypted = row.get("encrypted_key")
    if not encrypted:
        return None
    return {
        "key_id": str(row.get("key_id") or ""),
        "key": _fernet().decrypt(encrypted.encode("utf-8")).decode("utf-8"),
    }


def list_checkpoint_signing_keys(tenant_id: str) -> List[Dict[str, str]]:
    init_db()
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
