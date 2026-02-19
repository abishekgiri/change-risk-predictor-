from __future__ import annotations

import base64
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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


def create_webhook_key(
    *,
    tenant_id: str,
    integration_id: str,
    created_by: Optional[str] = None,
    raw_secret: Optional[str] = None,
    key_id: Optional[str] = None,
    deactivate_existing: bool = False,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    effective_integration = str(integration_id or "").strip()
    if not effective_integration:
        raise ValueError("integration_id is required")

    secret_value = (raw_secret or secrets.token_urlsafe(48)).strip()
    if not secret_value:
        raise ValueError("webhook secret cannot be empty")

    effective_key_id = str(key_id or f"whk_{uuid.uuid4().hex}").strip()
    created_at = datetime.now(timezone.utc).isoformat()
    encrypted = _fernet().encrypt(secret_value.encode("utf-8")).decode("utf-8")

    if deactivate_existing:
        storage.execute(
            """
            UPDATE webhook_signing_keys
            SET is_active = ?, rotated_at = COALESCE(rotated_at, ?)
            WHERE tenant_id = ? AND integration_id = ? AND is_active = ?
            """,
            (False, created_at, effective_tenant, effective_integration, True),
        )

    storage.execute(
        """
        INSERT INTO webhook_signing_keys (
            tenant_id, integration_id, key_id, encrypted_secret, secret_hash,
            created_by, created_at, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            effective_integration,
            effective_key_id,
            encrypted,
            hashlib.sha256(secret_value.encode("utf-8")).hexdigest(),
            created_by,
            created_at,
            True,
        ),
    )

    return {
        "tenant_id": effective_tenant,
        "integration_id": effective_integration,
        "key_id": effective_key_id,
        "created_at": created_at,
        "webhook_secret": secret_value,  # returned once to caller
    }


def lookup_active_webhook_key(key_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, integration_id, key_id, encrypted_secret, created_at
        FROM webhook_signing_keys
        WHERE key_id = ? AND is_active = ?
        LIMIT 1
        """,
        (str(key_id or "").strip(), True),
    )
    if not row:
        return None
    encrypted = row.get("encrypted_secret")
    if not encrypted:
        return None
    row["secret"] = _fernet().decrypt(encrypted.encode("utf-8")).decode("utf-8")
    return row


def list_webhook_keys(*, tenant_id: str, integration_id: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    params: List[str] = [effective_tenant]
    query = """
        SELECT tenant_id, integration_id, key_id, created_by, created_at, rotated_at, is_active
        FROM webhook_signing_keys
        WHERE tenant_id = ?
    """
    if integration_id:
        query += " AND integration_id = ?"
        params.append(str(integration_id).strip())
    query += " ORDER BY created_at DESC"
    return storage.fetchall(query, tuple(params))
