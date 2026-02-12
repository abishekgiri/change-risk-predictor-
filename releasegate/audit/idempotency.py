from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import time
from typing import Any, Dict, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import sha256_json


@dataclass
class IdempotencyClaim:
    state: str  # new | replay | in_progress
    record: Dict[str, Any]
    response: Optional[Dict[str, Any]] = None


def _ttl_seconds() -> int:
    raw = os.getenv("RELEASEGATE_IDEMPOTENCY_TTL_SECONDS", "86400")
    try:
        parsed = int(raw)
        return parsed if parsed > 0 else 86400
    except Exception:
        return 86400


def _decode_response_json(raw: Any) -> Optional[Dict[str, Any]]:
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _fetch_record(*, tenant_id: str, operation: str, idem_key: str) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    return storage.fetchone(
        """
        SELECT tenant_id, operation, idem_key, request_fingerprint, status, response_json, resource_type, resource_id, created_at, updated_at, expires_at
        FROM idempotency_keys
        WHERE tenant_id = ? AND operation = ? AND idem_key = ?
        LIMIT 1
        """,
        (tenant_id, operation, idem_key),
    )


def _cleanup_expired() -> None:
    storage = get_storage_backend()
    storage.execute(
        "DELETE FROM idempotency_keys WHERE expires_at <= ?",
        (datetime.now(timezone.utc).isoformat(),),
    )


def claim_idempotency(
    *,
    tenant_id: str,
    operation: str,
    idem_key: str,
    request_payload: Dict[str, Any],
) -> IdempotencyClaim:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_operation = str(operation or "").strip()
    normalized_key = str(idem_key or "").strip()
    if not normalized_operation:
        raise ValueError("operation is required")
    if not normalized_key:
        raise ValueError("idempotency key is required")

    _cleanup_expired()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=_ttl_seconds())
    fingerprint = sha256_json(request_payload or {})

    try:
        storage.execute(
            """
            INSERT INTO idempotency_keys (
                tenant_id, operation, idem_key, request_fingerprint, status, created_at, updated_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                normalized_operation,
                normalized_key,
                fingerprint,
                "in_progress",
                now.isoformat(),
                now.isoformat(),
                expires.isoformat(),
            ),
        )
        row = _fetch_record(tenant_id=effective_tenant, operation=normalized_operation, idem_key=normalized_key) or {}
        return IdempotencyClaim(state="new", record=row)
    except Exception:
        existing = _fetch_record(tenant_id=effective_tenant, operation=normalized_operation, idem_key=normalized_key)
        if not existing:
            raise
        if existing.get("request_fingerprint") != fingerprint:
            raise ValueError("Idempotency-Key reuse with a different request payload is not allowed")
        response = _decode_response_json(existing.get("response_json"))
        if str(existing.get("status") or "").lower() == "completed" and response is not None:
            return IdempotencyClaim(state="replay", record=existing, response=response)
        return IdempotencyClaim(state="in_progress", record=existing)


def complete_idempotency(
    *,
    tenant_id: str,
    operation: str,
    idem_key: str,
    response_payload: Dict[str, Any],
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
) -> None:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    now = datetime.now(timezone.utc).isoformat()
    storage.execute(
        """
        UPDATE idempotency_keys
        SET status = ?, response_json = ?, resource_type = ?, resource_id = ?, updated_at = ?
        WHERE tenant_id = ? AND operation = ? AND idem_key = ?
        """,
        (
            "completed",
            json.dumps(response_payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            resource_type,
            resource_id,
            now,
            effective_tenant,
            operation,
            idem_key,
        ),
    )


def wait_for_idempotency_response(
    *,
    tenant_id: str,
    operation: str,
    idem_key: str,
    timeout_seconds: float = 1.5,
    poll_interval_seconds: float = 0.05,
) -> Optional[Dict[str, Any]]:
    deadline = time.monotonic() + max(timeout_seconds, 0.0)
    effective_tenant = resolve_tenant_id(tenant_id)
    while time.monotonic() <= deadline:
        row = _fetch_record(tenant_id=effective_tenant, operation=operation, idem_key=idem_key)
        if row and str(row.get("status") or "").lower() == "completed":
            response = _decode_response_json(row.get("response_json"))
            if response is not None:
                return response
        time.sleep(max(poll_interval_seconds, 0.01))
    return None


def derive_system_idempotency_key(*, tenant_id: str, operation: str, identity: Dict[str, Any]) -> str:
    payload = {
        "tenant_id": resolve_tenant_id(tenant_id),
        "operation": str(operation),
        "identity": identity or {},
    }
    return sha256_json(payload)
