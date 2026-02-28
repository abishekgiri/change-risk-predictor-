from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.anchoring.provider import AnchorProviderError, anchor_root, verify_root_anchor_receipt
from releasegate.audit.transparency import get_or_compute_transparency_root
from releasegate.config import get_anchor_provider_name
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json


def _ensure_external_root_anchors_table() -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_external_root_anchors (
            tenant_id TEXT NOT NULL,
            anchor_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            date_utc TEXT NOT NULL,
            root_hash TEXT NOT NULL,
            external_ref TEXT,
            receipt_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, anchor_id)
        )
        """
    )
    storage.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_external_root_anchor_target
        ON audit_external_root_anchors(tenant_id, provider, date_utc, root_hash)
        """
    )
    storage.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_external_root_anchor_tenant_date
        ON audit_external_root_anchors(tenant_id, date_utc, created_at DESC)
        """
    )
    if storage.name == "postgres":
        storage.execute(
            """
            CREATE OR REPLACE FUNCTION releasegate_prevent_external_root_anchor_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'External root anchors are append-only: % not allowed', TG_OP;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        storage.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger WHERE tgname = 'prevent_external_root_anchor_update'
                ) THEN
                    CREATE TRIGGER prevent_external_root_anchor_update
                    BEFORE UPDATE ON audit_external_root_anchors
                    FOR EACH ROW
                    EXECUTE FUNCTION releasegate_prevent_external_root_anchor_mutation();
                END IF;
            END $$;
            """
        )
        storage.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger WHERE tgname = 'prevent_external_root_anchor_delete'
                ) THEN
                    CREATE TRIGGER prevent_external_root_anchor_delete
                    BEFORE DELETE ON audit_external_root_anchors
                    FOR EACH ROW
                    EXECUTE FUNCTION releasegate_prevent_external_root_anchor_mutation();
                END IF;
            END $$;
            """
        )
        return

    storage.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_external_root_anchor_update
        BEFORE UPDATE ON audit_external_root_anchors
        BEGIN
            SELECT RAISE(FAIL, 'External root anchors are append-only: UPDATE not allowed');
        END;
        """
    )
    storage.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_external_root_anchor_delete
        BEFORE DELETE ON audit_external_root_anchors
        BEGIN
            SELECT RAISE(FAIL, 'External root anchors are append-only: DELETE not allowed');
        END;
        """
    )


def _anchor_id(*, tenant_id: str, provider: str, date_utc: str, root_hash: str) -> str:
    material = f"{tenant_id}:{provider}:{date_utc}:{root_hash}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _row_to_item(row: Dict[str, Any]) -> Dict[str, Any]:
    receipt_raw = row.get("receipt_json")
    receipt: Dict[str, Any] = {}
    if isinstance(receipt_raw, str):
        try:
            decoded = json.loads(receipt_raw)
            if isinstance(decoded, dict):
                receipt = decoded
        except Exception:
            receipt = {}
    elif isinstance(receipt_raw, dict):
        receipt = dict(receipt_raw)
    return {
        "tenant_id": row.get("tenant_id"),
        "anchor_id": row.get("anchor_id"),
        "provider": row.get("provider"),
        "date_utc": row.get("date_utc"),
        "root_hash": row.get("root_hash"),
        "external_ref": row.get("external_ref"),
        "receipt": receipt,
        "created_at": row.get("created_at"),
    }


def _get_by_target(
    *,
    tenant_id: str,
    provider: str,
    date_utc: str,
    root_hash: str,
) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, anchor_id, provider, date_utc, root_hash, external_ref, receipt_json, created_at
        FROM audit_external_root_anchors
        WHERE tenant_id = ? AND provider = ? AND date_utc = ? AND root_hash = ?
        LIMIT 1
        """,
        (tenant_id, provider, date_utc, root_hash),
    )
    if not row:
        return None
    return _row_to_item(row)


def record_root_anchor(
    *,
    tenant_id: Optional[str],
    provider: str,
    date_utc: str,
    root_hash: str,
    receipt: Dict[str, Any],
    external_ref: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    _ensure_external_root_anchors_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    provider_name = str(provider or "").strip().lower()
    if not provider_name:
        raise ValueError("provider is required")
    normalized_date = str(date_utc or "").strip()
    if not normalized_date:
        raise ValueError("date_utc is required")
    normalized_root = str(root_hash or "").strip()
    if not normalized_root:
        raise ValueError("root_hash is required")

    existing = _get_by_target(
        tenant_id=effective_tenant,
        provider=provider_name,
        date_utc=normalized_date,
        root_hash=normalized_root,
    )
    if existing:
        return existing

    anchor_id = _anchor_id(
        tenant_id=effective_tenant,
        provider=provider_name,
        date_utc=normalized_date,
        root_hash=normalized_root,
    )
    created_at = datetime.now(timezone.utc).isoformat()
    storage.execute(
        """
        INSERT INTO audit_external_root_anchors (
            tenant_id, anchor_id, provider, date_utc, root_hash, external_ref, receipt_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, anchor_id) DO NOTHING
        """,
        (
            effective_tenant,
            anchor_id,
            provider_name,
            normalized_date,
            normalized_root,
            (str(external_ref).strip() or None) if external_ref is not None else None,
            canonical_json(receipt if isinstance(receipt, dict) else {}),
            created_at,
        ),
    )
    item = _get_by_target(
        tenant_id=effective_tenant,
        provider=provider_name,
        date_utc=normalized_date,
        root_hash=normalized_root,
    )
    if not item:
        raise RuntimeError("failed to persist external root anchor")
    return item


def anchor_transparency_root(
    *,
    date_utc: str,
    tenant_id: Optional[str],
    provider_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_external_root_anchors_table()
    effective_tenant = resolve_tenant_id(tenant_id)
    root_entry = get_or_compute_transparency_root(date_utc=date_utc, tenant_id=effective_tenant)
    if not root_entry:
        return None
    normalized_date = str(root_entry.get("date_utc") or date_utc)
    root_hash = str(root_entry.get("root_hash") or "").strip()
    if not root_hash:
        raise AnchorProviderError("transparency root hash is unavailable")
    selected_provider = str(provider_name or get_anchor_provider_name()).strip().lower()
    if selected_provider:
        existing = _get_by_target(
            tenant_id=effective_tenant,
            provider=selected_provider,
            date_utc=normalized_date,
            root_hash=root_hash,
        )
        if existing:
            return existing

    receipt = anchor_root(
        date_utc=normalized_date,
        root_hash=root_hash,
        tenant_id=effective_tenant,
        provider_name=selected_provider or provider_name,
    )
    if not receipt:
        return None
    provider = str(receipt.get("provider") or selected_provider or "").strip().lower()
    if not provider:
        raise AnchorProviderError("anchor receipt missing provider")

    existing = _get_by_target(
        tenant_id=effective_tenant,
        provider=provider,
        date_utc=normalized_date,
        root_hash=root_hash,
    )
    if existing:
        return existing

    if not verify_root_anchor_receipt(
        receipt=receipt,
        expected_root_hash=root_hash,
        provider_name=provider,
    ):
        raise AnchorProviderError("anchor receipt verification failed")

    return record_root_anchor(
        tenant_id=effective_tenant,
        provider=provider,
        date_utc=normalized_date,
        root_hash=root_hash,
        external_ref=str(receipt.get("external_ref") or "").strip() or None,
        receipt=receipt,
    )


def get_root_anchor_by_target(
    *,
    tenant_id: Optional[str],
    provider: str,
    date_utc: str,
    root_hash: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_external_root_anchors_table()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_provider = str(provider or "").strip().lower()
    normalized_date = str(date_utc or "").strip()
    normalized_root_hash = str(root_hash or "").strip()
    if not normalized_provider or not normalized_date or not normalized_root_hash:
        return None
    return _get_by_target(
        tenant_id=effective_tenant,
        provider=normalized_provider,
        date_utc=normalized_date,
        root_hash=normalized_root_hash,
    )


def get_root_anchor_for_date(
    *,
    date_utc: str,
    tenant_id: Optional[str],
    provider_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    init_db()
    _ensure_external_root_anchors_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_date = str(date_utc or "").strip()
    if not normalized_date:
        return None
    if provider_name:
        row = storage.fetchone(
            """
            SELECT tenant_id, anchor_id, provider, date_utc, root_hash, external_ref, receipt_json, created_at
            FROM audit_external_root_anchors
            WHERE tenant_id = ? AND provider = ? AND date_utc = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (effective_tenant, str(provider_name).strip().lower(), normalized_date),
        )
    else:
        row = storage.fetchone(
            """
            SELECT tenant_id, anchor_id, provider, date_utc, root_hash, external_ref, receipt_json, created_at
            FROM audit_external_root_anchors
            WHERE tenant_id = ? AND date_utc = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (effective_tenant, normalized_date),
        )
    if not row:
        return None
    return _row_to_item(row)


def list_root_anchors(
    *,
    tenant_id: Optional[str],
    date_utc: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    init_db()
    _ensure_external_root_anchors_table()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    try:
        bounded_limit = max(1, min(int(limit), 500))
    except Exception as exc:
        raise ValueError("limit must be an integer") from exc

    params: List[Any] = [effective_tenant]
    where_clause = "tenant_id = ?"
    if date_utc:
        where_clause += " AND date_utc = ?"
        params.append(str(date_utc).strip())
    params.append(bounded_limit)
    rows = storage.fetchall(
        f"""
        SELECT tenant_id, anchor_id, provider, date_utc, root_hash, external_ref, receipt_json, created_at
        FROM audit_external_root_anchors
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT ?
        """,
        params,
    )
    return [_row_to_item(row) for row in rows]
