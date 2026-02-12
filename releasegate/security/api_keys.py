from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _key_pepper() -> str:
    return os.getenv("RELEASEGATE_API_KEY_PEPPER", "")


def _pbkdf2_iterations() -> int:
    raw = os.getenv("RELEASEGATE_API_KEY_PBKDF2_ITERATIONS", "310000")
    try:
        parsed = int(raw)
        return parsed if parsed >= 310000 else 310000
    except Exception:
        return 310000


def _pbkdf2_material(raw_key: str) -> bytes:
    return f"{raw_key}:{_key_pepper()}".encode("utf-8")


def _derive_pbkdf2_hash(raw_key: str, *, salt: bytes, iterations: int) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        _pbkdf2_material(raw_key),
        salt,
        iterations,
    )
    return digest.hex()


def _legacy_hash_api_key(raw_key: str) -> str:
    material = _pbkdf2_material(raw_key)
    return hashlib.sha256(material).hexdigest()


def _extract_key_id(raw_key: str) -> Optional[str]:
    raw = str(raw_key or "").strip()
    if not raw.startswith("rgk_"):
        return None
    payload = raw[4:]
    if "." not in payload:
        return None
    key_id, _secret = payload.split(".", 1)
    key_id = key_id.strip()
    return key_id or None


def create_api_key(
    *,
    tenant_id: str,
    name: str,
    roles: List[str],
    scopes: List[str],
    created_by: Optional[str],
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    key_id = uuid.uuid4().hex
    key_secret = secrets.token_urlsafe(32)
    raw_key = f"rgk_{key_id}.{key_secret}"
    created_at = datetime.now(timezone.utc).isoformat()
    salt = secrets.token_bytes(16)
    iterations = _pbkdf2_iterations()
    storage.execute(
        """
        INSERT INTO api_keys (
            tenant_id, key_id, name, key_prefix, key_hash, key_algorithm, key_iterations, key_salt,
            roles_json, scopes_json, created_by, created_at, is_enabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (
            effective_tenant,
            key_id,
            name,
            raw_key[:16],
            _derive_pbkdf2_hash(raw_key, salt=salt, iterations=iterations),
            "pbkdf2_sha256",
            iterations,
            salt.hex(),
            json.dumps(sorted(set(roles)), separators=(",", ":"), ensure_ascii=False),
            json.dumps(sorted(set(scopes)), separators=(",", ":"), ensure_ascii=False),
            created_by,
            created_at,
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "key_id": key_id,
        "name": name,
        "roles": sorted(set(roles)),
        "scopes": sorted(set(scopes)),
        "created_at": created_at,
        "api_key": raw_key,  # returned exactly once
    }


def _decode_json_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(x) for x in value]
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(x) for x in parsed]
    except Exception:
        return []
    return []


def _verify_key(row: Dict[str, Any], raw_key: str) -> bool:
    algorithm = str(row.get("key_algorithm") or "").strip().lower()
    if algorithm == "pbkdf2_sha256":
        try:
            iterations = int(row.get("key_iterations") or 0)
        except Exception:
            iterations = 0
        salt_hex = str(row.get("key_salt") or "").strip()
        if iterations <= 0 or not salt_hex:
            return False
        try:
            salt = bytes.fromhex(salt_hex)
        except Exception:
            return False
        expected = str(row.get("key_hash") or "")
        actual = _derive_pbkdf2_hash(raw_key, salt=salt, iterations=iterations)
        return hmac.compare_digest(expected, actual)

    expected_legacy = str(row.get("key_hash") or "")
    actual_legacy = _legacy_hash_api_key(raw_key)
    return hmac.compare_digest(expected_legacy, actual_legacy)


def _load_key_candidate(raw_key: str) -> Optional[Dict[str, Any]]:
    key_id = _extract_key_id(raw_key)
    if not key_id:
        return None
    init_db()
    storage = get_storage_backend()
    return storage.fetchone(
        """
        SELECT *
        FROM api_keys
        WHERE key_id = ? AND revoked_at IS NULL AND is_enabled = 1
        LIMIT 1
        """,
        (key_id,),
    )


def authenticate_api_key(raw_key: str) -> Optional[Dict[str, Any]]:
    row = _load_key_candidate(raw_key)
    if not row:
        return None
    if not _verify_key(row, raw_key):
        return None

    storage = get_storage_backend()
    storage.execute(
        """
        UPDATE api_keys
        SET last_used_at = ?
        WHERE tenant_id = ? AND key_id = ?
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            row["tenant_id"],
            row["key_id"],
        ),
    )
    row["roles"] = _decode_json_list(row.get("roles_json"))
    row["scopes"] = _decode_json_list(row.get("scopes_json"))
    return row


def list_api_keys(*, tenant_id: str) -> List[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    rows = storage.fetchall(
        """
        SELECT tenant_id, key_id, name, key_prefix, roles_json, scopes_json, created_by, created_at, last_used_at, revoked_at, is_enabled
        FROM api_keys
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        """,
        (resolve_tenant_id(tenant_id),),
    )
    for row in rows:
        row["roles"] = _decode_json_list(row.get("roles_json"))
        row["scopes"] = _decode_json_list(row.get("scopes_json"))
        row.pop("roles_json", None)
        row.pop("scopes_json", None)
    return rows


def get_api_key(*, tenant_id: str, key_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, key_id, name, roles_json, scopes_json, created_by, created_at, last_used_at, revoked_at, is_enabled
        FROM api_keys
        WHERE tenant_id = ? AND key_id = ?
        LIMIT 1
        """,
        (resolve_tenant_id(tenant_id), key_id),
    )
    if not row:
        return None
    row["roles"] = _decode_json_list(row.get("roles_json"))
    row["scopes"] = _decode_json_list(row.get("scopes_json"))
    row.pop("roles_json", None)
    row.pop("scopes_json", None)
    return row


def revoke_api_key(*, tenant_id: str, key_id: str) -> bool:
    init_db()
    storage = get_storage_backend()
    changed = storage.execute(
        """
        UPDATE api_keys
        SET revoked_at = COALESCE(revoked_at, ?), is_enabled = 0
        WHERE tenant_id = ? AND key_id = ? AND revoked_at IS NULL
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            resolve_tenant_id(tenant_id),
            key_id,
        ),
    )
    return changed > 0


def rotate_api_key(
    *,
    tenant_id: str,
    key_id: str,
    rotated_by: Optional[str],
) -> Optional[Dict[str, Any]]:
    existing = get_api_key(tenant_id=tenant_id, key_id=key_id)
    if not existing or existing.get("revoked_at"):
        return None

    created = create_api_key(
        tenant_id=tenant_id,
        name=str(existing.get("name") or f"rotated-{key_id}"),
        roles=list(existing.get("roles") or ["operator"]),
        scopes=list(existing.get("scopes") or ["enforcement:write"]),
        created_by=rotated_by,
    )
    revoke_api_key(tenant_id=tenant_id, key_id=key_id)
    created["rotated_from_key_id"] = key_id
    return created
