from __future__ import annotations

import json
import string
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.audit.transparency import record_transparency_for_attestation
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _ensure_audit_attestations_table() -> None:
    """
    Backward-compatible bootstrap for branches/environments where migration
    20260213_011 has not been applied yet.
    """
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_attestations (
            tenant_id TEXT NOT NULL,
            attestation_id TEXT NOT NULL,
            decision_id TEXT NOT NULL,
            repo TEXT,
            pr_number INTEGER,
            schema_version TEXT NOT NULL,
            key_id TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            signed_payload_hash TEXT NOT NULL,
            attestation_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, attestation_id)
        )
        """
    )
    storage.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_attestations_tenant_decision
        ON audit_attestations(tenant_id, decision_id)
        """
    )


def _normalize_signed_payload_hash(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("signed_payload_hash is required")
    if ":" in raw:
        algo, digest = raw.split(":", 1)
        if algo.strip().lower() != "sha256":
            raise ValueError("signed_payload_hash must use sha256")
        raw = digest
    normalized = raw.strip().lower()
    if len(normalized) != 64 or any(ch not in string.hexdigits for ch in normalized):
        raise ValueError("signed_payload_hash must be a 64-char sha256 hex digest")
    return normalized


def _attestation_id(*, signed_payload_hash: str) -> str:
    # Portable identity: derived from signed payload hash only.
    return _normalize_signed_payload_hash(signed_payload_hash)


def record_release_attestation(
    *,
    decision_id: str,
    tenant_id: str,
    repo: Optional[str],
    pr_number: Optional[int],
    attestation: Dict[str, Any],
) -> str:
    init_db()
    _ensure_audit_attestations_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)

    existing = storage.fetchone(
        """
        SELECT attestation_id
        FROM audit_attestations
        WHERE tenant_id = ? AND decision_id = ?
        LIMIT 1
        """,
        (effective_tenant, decision_id),
    )
    if existing and existing.get("attestation_id"):
        existing_id = str(existing["attestation_id"])
        signature = attestation.get("signature") or {}
        signed_payload_hash = str(signature.get("signed_payload_hash") or "")
        normalized_hash = _normalize_signed_payload_hash(signed_payload_hash)
        payload_hash = f"sha256:{normalized_hash}"
        record_transparency_for_attestation(
            tenant_id=effective_tenant,
            attestation_id=existing_id,
            fallback_repo=repo,
            fallback_pr_number=pr_number,
            payload_hash=payload_hash,
            attestation=attestation,
        )
        return existing_id

    signature = attestation.get("signature") or {}
    signed_payload_hash = str(signature.get("signed_payload_hash") or "")
    normalized_hash = _normalize_signed_payload_hash(signed_payload_hash)
    payload_hash = f"sha256:{normalized_hash}"
    algorithm = str(signature.get("algorithm") or "ed25519")
    key_id = str((attestation.get("issuer") or {}).get("key_id") or "")
    schema_version = str(attestation.get("schema_version") or "1.0.0")
    created_at = datetime.now(timezone.utc).isoformat()
    attestation_id = _attestation_id(signed_payload_hash=signed_payload_hash)

    storage.execute(
        """
        INSERT INTO audit_attestations (
            tenant_id, attestation_id, decision_id, repo, pr_number,
            schema_version, key_id, algorithm, signed_payload_hash,
            attestation_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, attestation_id) DO NOTHING
        """,
        (
            effective_tenant,
            attestation_id,
            decision_id,
            repo,
            pr_number,
            schema_version,
            key_id,
            algorithm,
            payload_hash,
            json.dumps(attestation, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
            created_at,
        ),
    )
    record_transparency_for_attestation(
        tenant_id=effective_tenant,
        attestation_id=attestation_id,
        fallback_repo=repo,
        fallback_pr_number=pr_number,
        payload_hash=payload_hash,
        attestation=attestation,
    )
    return attestation_id


def get_release_attestation_by_decision(
    *,
    decision_id: str,
    tenant_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_audit_attestations_table()
    storage = get_storage_backend()
    try:
        row = storage.fetchone(
            """
            SELECT *
            FROM audit_attestations
            WHERE tenant_id = ? AND decision_id = ?
            LIMIT 1
            """,
            (resolve_tenant_id(tenant_id), decision_id),
        )
    except Exception as exc:
        # Older local DBs may not have attestation tables yet; treat as no attestation.
        if "no such table" in str(exc).lower() and "audit_attestations" in str(exc).lower():
            return None
        raise
    if not row:
        return None
    raw = row.get("attestation_json")
    payload = json.loads(raw) if isinstance(raw, str) else raw
    row["attestation"] = payload
    return row


def get_release_attestation_by_id(
    *,
    attestation_id: str,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_audit_attestations_table()
    storage = get_storage_backend()
    try:
        if tenant_id is None:
            row = storage.fetchone(
                """
                SELECT *
                FROM audit_attestations
                WHERE attestation_id = ?
                LIMIT 1
                """,
                (attestation_id,),
            )
        else:
            row = storage.fetchone(
                """
                SELECT *
                FROM audit_attestations
                WHERE tenant_id = ? AND attestation_id = ?
                LIMIT 1
                """,
                (resolve_tenant_id(tenant_id), attestation_id),
            )
    except Exception as exc:
        if "no such table" in str(exc).lower() and "audit_attestations" in str(exc).lower():
            return None
        raise
    if not row:
        return None
    raw = row.get("attestation_json")
    payload = json.loads(raw) if isinstance(raw, str) else raw
    row["attestation"] = payload
    return row
