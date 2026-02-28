from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.attestation.canonicalize import canonicalize_attestation_payload
from releasegate.attestation.crypto import load_private_key_for_tenant, sign_bytes
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.tenants.keys import (
    get_active_tenant_signing_key_record,
    revoke_tenant_signing_key,
    rotate_tenant_signing_key,
)
from releasegate.utils.canonical import canonical_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_timestamp(value: Optional[str], *, field: str) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be ISO8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat()


def _ensure_compromise_tables() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_key_compromise_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            revoked_key_id TEXT NOT NULL,
            replacement_key_id TEXT NOT NULL,
            compromise_start TEXT NOT NULL,
            compromise_end TEXT NOT NULL,
            reason TEXT,
            actor TEXT,
            created_at TEXT NOT NULL,
            affected_count INTEGER NOT NULL DEFAULT 0,
            affected_attestation_ids_json TEXT NOT NULL DEFAULT '[]',
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tenant_key_compromise_events_tenant_created
        ON tenant_key_compromise_events(tenant_id, created_at DESC)
        """
    )
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS attestation_resignatures (
            tenant_id TEXT NOT NULL,
            resign_id TEXT NOT NULL,
            attestation_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            new_key_id TEXT NOT NULL,
            supersedes_attestation_id TEXT NOT NULL,
            attestation_json TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, resign_id)
        )
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_attestation_resignatures_tenant_attestation_created
        ON attestation_resignatures(tenant_id, attestation_id, created_at DESC)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_attestation_resignatures_tenant_decision_created
        ON attestation_resignatures(tenant_id, decision_id, created_at DESC)
        """
    )


def _attestations_for_key_window(
    *,
    tenant_id: str,
    key_id: str,
    start_at: str,
    end_at: str,
) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    return storage.fetchall(
        """
        SELECT tenant_id, attestation_id, decision_id, key_id, created_at, attestation_json
        FROM audit_attestations
        WHERE tenant_id = ? AND key_id = ? AND created_at >= ? AND created_at <= ?
        ORDER BY created_at ASC
        """,
        (tenant_id, key_id, start_at, end_at),
    )


def emergency_rotate_tenant_signing_key(
    *,
    tenant_id: str,
    actor_id: str,
    reason: Optional[str] = None,
    compromise_start: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    _ensure_compromise_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    with storage.transaction():
        now = _utc_now()
        active = get_active_tenant_signing_key_record(
            effective_tenant,
            actor=actor_id,
            purpose="emergency_rotate_precheck",
            access_operation="decrypt",
        )
        if not active:
            raise ValueError("active tenant signing key not found")
        revoked_key_id = str(active.get("key_id") or "").strip()
        if not revoked_key_id:
            raise ValueError("active tenant signing key id missing")

        start_at = _normalize_timestamp(compromise_start, field="compromise_start") or str(active.get("created_at") or now)
        if str(start_at) > str(now):
            raise ValueError("compromise_start cannot be in the future")

        replacement = rotate_tenant_signing_key(
            tenant_id=effective_tenant,
            created_by=actor_id,
            metadata={
                **(metadata or {}),
                "emergency_rotate": True,
                "reason": reason or "emergency-rotate",
                "replaces_key_id": revoked_key_id,
            },
        )
        replacement_key_id = str(replacement.get("key_id") or "").strip()
        revoke_tenant_signing_key(
            tenant_id=effective_tenant,
            key_id=revoked_key_id,
            revoked_by=actor_id,
            reason=reason or "emergency-rotate",
        )

        affected_rows = _attestations_for_key_window(
            tenant_id=effective_tenant,
            key_id=revoked_key_id,
            start_at=start_at,
            end_at=now,
        )
        affected_attestation_ids = [str(row.get("attestation_id") or "") for row in affected_rows if row.get("attestation_id")]

        event_id = uuid.uuid4().hex
        storage.execute(
            """
            INSERT INTO tenant_key_compromise_events (
                tenant_id, event_id, revoked_key_id, replacement_key_id, compromise_start, compromise_end,
                reason, actor, created_at, affected_count, affected_attestation_ids_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                event_id,
                revoked_key_id,
                replacement_key_id,
                start_at,
                now,
                reason or "",
                actor_id,
                now,
                len(affected_attestation_ids),
                canonical_json(affected_attestation_ids),
            ),
        )
    return {
        "tenant_id": effective_tenant,
        "event_id": event_id,
        "revoked_key_id": revoked_key_id,
        "replacement_key_id": replacement_key_id,
        "compromise_start": start_at,
        "compromise_end": now,
        "affected_count": len(affected_attestation_ids),
        "affected_attestation_ids": affected_attestation_ids,
    }


def list_compromise_events(
    *,
    tenant_id: str,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    init_db()
    _ensure_compromise_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    effective_limit = max(1, min(int(limit), 500))
    rows = storage.fetchall(
        """
        SELECT tenant_id, event_id, revoked_key_id, replacement_key_id, compromise_start, compromise_end,
               reason, actor, created_at, affected_count, affected_attestation_ids_json
        FROM tenant_key_compromise_events
        WHERE tenant_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (effective_tenant, effective_limit),
    )
    for row in rows:
        raw = row.get("affected_attestation_ids_json")
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = []
        elif isinstance(raw, list):
            parsed = list(raw)
        else:
            parsed = []
        row["affected_attestation_ids"] = [str(item) for item in parsed if str(item).strip()]
    return rows


def is_attestation_compromised(*, tenant_id: str, attestation_id: str) -> Dict[str, Any]:
    init_db()
    _ensure_compromise_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT key_id, created_at
        FROM audit_attestations
        WHERE tenant_id = ? AND attestation_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(attestation_id)),
    )
    if not row:
        return {"compromised": False, "event_id": None}
    key_id = str(row.get("key_id") or "").strip()
    created_at = str(row.get("created_at") or "").strip()
    if not key_id or not created_at:
        return {"compromised": False, "event_id": None}
    hit = storage.fetchone(
        """
        SELECT event_id, compromise_start, compromise_end
        FROM tenant_key_compromise_events
        WHERE tenant_id = ? AND revoked_key_id = ? AND compromise_start <= ? AND compromise_end >= ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (effective_tenant, key_id, created_at, created_at),
    )
    if not hit:
        return {"compromised": False, "event_id": None}
    return {
        "compromised": True,
        "event_id": hit.get("event_id"),
        "compromise_start": hit.get("compromise_start"),
        "compromise_end": hit.get("compromise_end"),
    }


def bulk_resign_compromised_attestations(
    *,
    tenant_id: str,
    actor_id: str,
    limit: int = 200,
) -> Dict[str, Any]:
    init_db()
    _ensure_compromise_tables()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    effective_limit = max(1, min(int(limit), 1000))
    active = get_active_tenant_signing_key_record(
        effective_tenant,
        actor=actor_id,
        purpose="attestation_resign_active_key_lookup",
        access_operation="sign",
    )
    if not active:
        raise ValueError("active tenant signing key not found")
    new_key_id = str(active.get("key_id") or "").strip()
    private_key, loaded_key_id = load_private_key_for_tenant(effective_tenant)
    if loaded_key_id != new_key_id:
        new_key_id = loaded_key_id

    rows = storage.fetchall(
        """
        SELECT a.attestation_id, a.decision_id, a.attestation_json
        FROM audit_attestations a
        WHERE a.tenant_id = ?
          AND EXISTS (
              SELECT 1
              FROM tenant_key_compromise_events e
              WHERE e.tenant_id = a.tenant_id
                AND e.revoked_key_id = a.key_id
                AND e.compromise_start <= a.created_at
                AND e.compromise_end >= a.created_at
          )
        ORDER BY a.created_at ASC
        LIMIT ?
        """,
        (effective_tenant, effective_limit),
    )

    created: List[Dict[str, Any]] = []
    for row in rows:
        raw = row.get("attestation_json")
        attestation = json.loads(raw) if isinstance(raw, str) else (raw or {})
        if not isinstance(attestation, dict):
            continue
        payload = dict(attestation)
        payload.pop("signature", None)
        issuer = payload.get("issuer")
        if isinstance(issuer, dict):
            issuer = dict(issuer)
            issuer["key_id"] = new_key_id
            payload["issuer"] = issuer
        payload_hash = canonicalize_attestation_payload(payload)
        digest = sign_bytes(private_key, hashlib.sha256(payload_hash).hexdigest())
        resigned = {
            **payload,
            "signature": {
                "algorithm": "ed25519",
                "signed_payload_hash": f"sha256:{hashlib.sha256(payload_hash).hexdigest()}",
                "signature_bytes": digest,
            },
        }
        resign_id = uuid.uuid4().hex
        created_at = _utc_now()
        storage.execute(
            """
            INSERT INTO attestation_resignatures (
                tenant_id, resign_id, attestation_id, decision_id, new_key_id, supersedes_attestation_id,
                attestation_json, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                resign_id,
                str(row.get("attestation_id") or ""),
                str(row.get("decision_id") or ""),
                new_key_id,
                str(row.get("attestation_id") or ""),
                canonical_json(resigned),
                actor_id,
                created_at,
            ),
        )
        created.append(
            {
                "resign_id": resign_id,
                "attestation_id": str(row.get("attestation_id") or ""),
                "decision_id": str(row.get("decision_id") or ""),
                "new_key_id": new_key_id,
                "supersedes_attestation_id": str(row.get("attestation_id") or ""),
                "created_at": created_at,
            }
        )
    return {
        "tenant_id": effective_tenant,
        "resigned_count": len(created),
        "items": created,
    }


def force_rekey_tenant(
    *,
    tenant_id: str,
    actor_id: str,
    reason: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    return rotate_tenant_signing_key(
        tenant_id=effective_tenant,
        created_by=actor_id,
        metadata={
            **(metadata or {}),
            "force_rekey": True,
            "reason": reason or "force-rekey",
        },
    )


def build_compromise_report(
    *,
    tenant_id: str,
    limit: int = 20,
) -> Dict[str, Any]:
    events = list_compromise_events(tenant_id=tenant_id, limit=limit)
    affected_total = sum(int(event.get("affected_count") or 0) for event in events)
    return {
        "tenant_id": resolve_tenant_id(tenant_id),
        "events": events,
        "total_events": len(events),
        "total_affected_attestations": affected_total,
    }
