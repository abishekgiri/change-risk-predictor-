from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json


KEY_STATUS_ACTIVE = "ACTIVE"
KEY_STATUS_VERIFY_ONLY = "VERIFY_ONLY"
KEY_STATUS_REVOKED = "REVOKED"
_KEY_STATUSES = {KEY_STATUS_ACTIVE, KEY_STATUS_VERIFY_ONLY, KEY_STATUS_REVOKED}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _decode_key_material(raw_value: str) -> bytes:
    value = str(raw_value or "").strip()
    if not value:
        raise ValueError("empty key material")
    if len(value) == 64:
        try:
            return bytes.fromhex(value)
        except Exception:
            pass
    try:
        decoded = base64.b64decode(value, validate=True)
        if decoded:
            return decoded
    except Exception:
        pass
    return value.encode("utf-8")


def _parse_private_key(raw_key: str) -> Ed25519PrivateKey:
    value = str(raw_key or "").strip()
    if not value:
        raise ValueError("private key is required")
    if value.startswith("-----BEGIN"):
        loaded = serialization.load_pem_private_key(value.encode("utf-8"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("private key must be Ed25519")
        return loaded
    material = _decode_key_material(value)
    if len(material) != 32:
        raise ValueError("private key must decode to 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(material)


def _private_key_to_pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _public_key_to_pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _ensure_tenant_signing_keys_table() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_signing_keys (
            tenant_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            status TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            revoked_at TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY (tenant_id, key_id)
        )
        """
    )
    storage.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_signing_keys_one_active
        ON tenant_signing_keys(tenant_id)
        WHERE status = 'ACTIVE'
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_signing_keys_tenant_status_created
        ON tenant_signing_keys(tenant_id, status, created_at DESC)
        """
    )


def _row_to_item(row: Dict[str, Any], *, include_private_key: bool = False) -> Dict[str, Any]:
    metadata_raw = row.get("metadata_json")
    metadata: Dict[str, Any] = {}
    if isinstance(metadata_raw, str):
        try:
            parsed = json.loads(metadata_raw)
            if isinstance(parsed, dict):
                metadata = parsed
        except Exception:
            metadata = {}
    elif isinstance(metadata_raw, dict):
        metadata = dict(metadata_raw)
    status = str(row.get("status") or "").strip().upper()
    if status not in _KEY_STATUSES:
        status = KEY_STATUS_REVOKED
    item = {
        "tenant_id": row.get("tenant_id"),
        "key_id": row.get("key_id"),
        "public_key": row.get("public_key"),
        "status": status,
        "created_by": row.get("created_by"),
        "created_at": row.get("created_at"),
        "rotated_at": row.get("rotated_at"),
        "revoked_at": row.get("revoked_at"),
        "metadata": metadata,
    }
    if include_private_key:
        encrypted = str(row.get("encrypted_private_key") or "").strip()
        if encrypted:
            item["private_key"] = _fernet().decrypt(encrypted.encode("utf-8")).decode("utf-8")
    return item


def list_tenant_signing_keys(tenant_id: str) -> List[Dict[str, Any]]:
    init_db()
    _ensure_tenant_signing_keys_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    rows = storage.fetchall(
        """
        SELECT tenant_id, key_id, public_key, encrypted_private_key, status, created_by, created_at, rotated_at, revoked_at, metadata_json
        FROM tenant_signing_keys
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        """,
        (effective_tenant,),
    )
    return [_row_to_item(row, include_private_key=False) for row in rows]


def get_tenant_signing_key_record(tenant_id: str, key_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_tenant_signing_keys_table()
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, key_id, public_key, encrypted_private_key, status, created_by, created_at, rotated_at, revoked_at, metadata_json
        FROM tenant_signing_keys
        WHERE tenant_id = ? AND key_id = ?
        LIMIT 1
        """,
        (resolve_tenant_id(tenant_id), str(key_id)),
    )
    if not row:
        return None
    return _row_to_item(row, include_private_key=True)


def get_active_tenant_signing_key_record(tenant_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_tenant_signing_keys_table()
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, key_id, public_key, encrypted_private_key, status, created_by, created_at, rotated_at, revoked_at, metadata_json
        FROM tenant_signing_keys
        WHERE tenant_id = ? AND status = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (resolve_tenant_id(tenant_id), KEY_STATUS_ACTIVE),
    )
    if not row:
        return None
    return _row_to_item(row, include_private_key=True)


def rotate_tenant_signing_key(
    *,
    tenant_id: str,
    created_by: Optional[str],
    raw_private_key: Optional[str] = None,
    key_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    _ensure_tenant_signing_keys_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now = _utc_now()
    new_key_id = str(key_id or uuid.uuid4().hex).strip()
    if not new_key_id:
        raise ValueError("key_id is required")

    generated = False
    if raw_private_key is None:
        private_key = Ed25519PrivateKey.generate()
        private_key_pem = _private_key_to_pem(private_key)
        generated = True
    else:
        private_key = _parse_private_key(raw_private_key)
        private_key_pem = _private_key_to_pem(private_key)
    public_key_pem = _public_key_to_pem(private_key)
    encrypted_private_key = _fernet().encrypt(private_key_pem.encode("utf-8")).decode("utf-8")
    merged_metadata = {
        "generated": generated,
        **(metadata or {}),
    }

    with storage.transaction():
        storage.execute(
            """
            UPDATE tenant_signing_keys
            SET status = ?, rotated_at = COALESCE(rotated_at, ?)
            WHERE tenant_id = ? AND status = ?
            """,
            (KEY_STATUS_VERIFY_ONLY, now, effective_tenant, KEY_STATUS_ACTIVE),
        )
        storage.execute(
            """
            INSERT INTO tenant_signing_keys (
                tenant_id, key_id, public_key, encrypted_private_key, status, created_by, created_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                new_key_id,
                public_key_pem,
                encrypted_private_key,
                KEY_STATUS_ACTIVE,
                created_by,
                now,
                canonical_json(merged_metadata),
            ),
        )
    item = get_tenant_signing_key_record(effective_tenant, new_key_id)
    if not item:
        raise RuntimeError("failed to persist tenant signing key")
    item["private_key"] = private_key_pem if generated else None
    return item


def revoke_tenant_signing_key(
    *,
    tenant_id: str,
    key_id: str,
    revoked_by: Optional[str],
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    _ensure_tenant_signing_keys_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    record = get_tenant_signing_key_record(effective_tenant, key_id)
    if not record:
        raise ValueError("tenant signing key not found")
    status = str(record.get("status") or "").upper()
    if status == KEY_STATUS_ACTIVE:
        raise ValueError("cannot revoke active signing key; rotate first")
    if status == KEY_STATUS_REVOKED:
        return record
    now = _utc_now()
    metadata = dict(record.get("metadata") or {})
    metadata["revoked_by"] = revoked_by
    if reason:
        metadata["revocation_reason"] = reason
    with storage.transaction():
        storage.execute(
            """
            UPDATE tenant_signing_keys
            SET status = ?, revoked_at = ?, metadata_json = ?
            WHERE tenant_id = ? AND key_id = ?
            """,
            (
                KEY_STATUS_REVOKED,
                now,
                canonical_json(metadata),
                effective_tenant,
                str(key_id),
            ),
        )
    refreshed = get_tenant_signing_key_record(effective_tenant, key_id)
    if not refreshed:
        raise RuntimeError("failed to load revoked tenant signing key")
    return refreshed


def get_tenant_signing_public_keys(
    tenant_id: str,
    *,
    include_verify_only: bool = True,
    include_revoked: bool = False,
) -> Dict[str, str]:
    mapping = get_tenant_signing_public_keys_with_status(
        tenant_id=tenant_id,
        include_verify_only=include_verify_only,
        include_revoked=include_revoked,
    )
    return {key_id: item["public_key"] for key_id, item in mapping.items()}


def get_tenant_signing_public_keys_with_status(
    *,
    tenant_id: str,
    include_verify_only: bool = True,
    include_revoked: bool = False,
) -> Dict[str, Dict[str, Any]]:
    init_db()
    _ensure_tenant_signing_keys_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    statuses = [KEY_STATUS_ACTIVE]
    if include_verify_only:
        statuses.append(KEY_STATUS_VERIFY_ONLY)
    if include_revoked:
        statuses.append(KEY_STATUS_REVOKED)
    placeholders = ",".join(["?"] * len(statuses))
    params: List[Any] = [effective_tenant, *statuses]
    rows = storage.fetchall(
        f"""
        SELECT tenant_id, key_id, public_key, encrypted_private_key, status, created_by, created_at, rotated_at, revoked_at, metadata_json
        FROM tenant_signing_keys
        WHERE tenant_id = ? AND status IN ({placeholders})
        ORDER BY created_at DESC
        """,
        params,
    )
    result: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        item = _row_to_item(row, include_private_key=False)
        key_id = str(item.get("key_id") or "")
        if not key_id:
            continue
        result[key_id] = {
            "public_key": str(item.get("public_key") or ""),
            "status": str(item.get("status") or ""),
            "revoked_at": item.get("revoked_at"),
            "created_at": item.get("created_at"),
        }
    return result
