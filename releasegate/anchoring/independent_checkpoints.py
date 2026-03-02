from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.anchoring.roots import anchor_transparency_root
from releasegate.audit.transparency import get_or_compute_transparency_root
from releasegate.security.checkpoint_keys import get_active_checkpoint_signing_key_record
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


SIGNATURE_ALGORITHM = "HMAC-SHA256"
SCHEMA_NAME = "independent_daily_checkpoint"
SCHEMA_VERSION = "v1"
CANONICALIZATION = "releasegate-canonical-json-v1"
HASH_ALGORITHM = "sha256"


def _normalize_date_utc(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError("date_utc is required in YYYY-MM-DD format")
    try:
        parsed = datetime.strptime(normalized, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("date_utc must be in YYYY-MM-DD format") from exc
    return parsed.date().isoformat()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _signing_material(*, tenant_id: str, signing_key: Optional[str]) -> Dict[str, str]:
    explicit = str(signing_key or "").strip()
    if explicit:
        return {"key": explicit, "key_id": "manual"}
    record = get_active_checkpoint_signing_key_record(
        tenant_id=tenant_id,
        operation="sign",
        actor="system:independent_checkpoint",
        purpose="independent_daily_checkpoint_signing",
    )
    if record and record.get("key"):
        return {
            "key": str(record.get("key") or ""),
            "key_id": str(record.get("key_id") or ""),
        }
    env_key = str(os.getenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY") or "").strip()
    if env_key:
        return {
            "key": env_key,
            "key_id": str(os.getenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID") or "env"),
        }
    raise ValueError("No checkpoint signing key available for tenant")


def _payload_hash(payload: Dict[str, Any]) -> str:
    return f"sha256:{sha256_json(payload)}"


def _checkpoint_id(*, tenant_id: str, date_utc: str, ledger_root: str) -> str:
    material = f"{tenant_id}:{date_utc}:{ledger_root}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _signature_for_payload(*, payload: Dict[str, Any], material: Dict[str, str]) -> Dict[str, str]:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "value": hmac.new(str(material["key"]).encode("utf-8"), canonical, hashlib.sha256).hexdigest(),
        "key_id": str(material.get("key_id") or ""),
    }


def _parse_json(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _row_to_checkpoint(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "v": 1,
        "tenant_id": row.get("tenant_id"),
        "checkpoint_id": row.get("checkpoint_id"),
        "date_utc": row.get("date_utc"),
        "as_of_utc": row.get("as_of_utc"),
        "ledger_root": row.get("ledger_root"),
        "ledger_size": int(row.get("ledger_size") or 0),
        "prev_checkpoint_hash": row.get("prev_checkpoint_hash") or "",
    }
    signature = {
        "algorithm": row.get("signature_algorithm") or SIGNATURE_ALGORITHM,
        "value": row.get("signature_value") or "",
        "key_id": row.get("signing_key_id") or "",
    }
    anchor_receipt = _parse_json(row.get("anchor_receipt_json"))
    return {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "generated_at": row.get("created_at"),
        "tenant_id": row.get("tenant_id"),
        "ids": {
            "checkpoint_id": row.get("checkpoint_id"),
            "decision_id": "",
            "proof_pack_id": "",
            "policy_bundle_hash": "",
            "date_utc": row.get("date_utc"),
        },
        "integrity": {
            "canonicalization": CANONICALIZATION,
            "hash_alg": HASH_ALGORITHM,
            "input_hash": "",
            "policy_hash": "",
            "decision_hash": "",
            "replay_hash": "",
            "ledger": {
                "ledger_tip_hash": row.get("ledger_root") or "",
                "ledger_record_id": row.get("date_utc") or "",
            },
            "signatures": {
                "checkpoint_signature": signature.get("value") or "",
                "signing_key_id": signature.get("key_id") or "",
            },
            "checkpoint_hash": row.get("checkpoint_hash") or "",
        },
        "payload": payload,
        "signature": signature,
        "external_anchor": {
            "provider": row.get("anchor_provider") or "",
            "external_ref": row.get("anchor_ref") or "",
            "receipt": anchor_receipt,
        },
    }


def _load_checkpoint_row(*, tenant_id: str, date_utc: str) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    return storage.fetchone(
        """
        SELECT
            tenant_id,
            checkpoint_id,
            date_utc,
            as_of_utc,
            ledger_root,
            ledger_size,
            prev_checkpoint_hash,
            checkpoint_hash,
            signature_algorithm,
            signature_value,
            signing_key_id,
            anchor_provider,
            anchor_ref,
            anchor_receipt_json,
            created_at
        FROM audit_independent_daily_checkpoints
        WHERE tenant_id = ? AND date_utc = ?
        LIMIT 1
        """,
        (tenant_id, date_utc),
    )


def _latest_prior_checkpoint_hash(*, tenant_id: str, date_utc: str) -> Optional[str]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT checkpoint_hash
        FROM audit_independent_daily_checkpoints
        WHERE tenant_id = ? AND date_utc < ?
        ORDER BY date_utc DESC
        LIMIT 1
        """,
        (tenant_id, date_utc),
    )
    if not row:
        return None
    return str(row.get("checkpoint_hash") or "").strip() or None


def get_independent_daily_checkpoint(
    *,
    date_utc: str,
    tenant_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_date = _normalize_date_utc(date_utc)
    row = _load_checkpoint_row(tenant_id=effective_tenant, date_utc=normalized_date)
    if not row:
        return None
    payload = _row_to_checkpoint(row)
    payload["created"] = False
    return payload


def create_independent_daily_checkpoint(
    *,
    date_utc: str,
    tenant_id: Optional[str],
    publish_anchor: bool = True,
    provider_name: Optional[str] = None,
    signing_key: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_date = _normalize_date_utc(date_utc)
    existing = _load_checkpoint_row(tenant_id=effective_tenant, date_utc=normalized_date)
    if existing:
        payload = _row_to_checkpoint(existing)
        payload["created"] = False
        return payload

    root = get_or_compute_transparency_root(date_utc=normalized_date, tenant_id=effective_tenant)
    if not root:
        raise ValueError("transparency root not found for date")
    ledger_root = str(root.get("root_hash") or "").strip()
    if not ledger_root:
        raise ValueError("transparency root hash unavailable")
    ledger_size = int(root.get("leaf_count") or 0)

    prev_checkpoint_hash = _latest_prior_checkpoint_hash(tenant_id=effective_tenant, date_utc=normalized_date) or ""
    checkpoint_id = _checkpoint_id(
        tenant_id=effective_tenant,
        date_utc=normalized_date,
        ledger_root=ledger_root,
    )
    payload = {
        "v": 1,
        "tenant_id": effective_tenant,
        "checkpoint_id": checkpoint_id,
        "date_utc": normalized_date,
        "as_of_utc": f"{normalized_date}T00:00:00+00:00",
        "ledger_root": ledger_root,
        "ledger_size": ledger_size,
        "prev_checkpoint_hash": prev_checkpoint_hash,
    }
    checkpoint_hash = _payload_hash(payload)
    material = _signing_material(tenant_id=effective_tenant, signing_key=signing_key)
    signature = _signature_for_payload(payload=payload, material=material)

    anchor_provider = ""
    anchor_ref = ""
    anchor_receipt: Dict[str, Any] = {}
    if publish_anchor:
        anchored = anchor_transparency_root(
            date_utc=normalized_date,
            tenant_id=effective_tenant,
            provider_name=provider_name,
        )
        if not anchored:
            raise ValueError("external anchor publish failed")
        anchor_provider = str(anchored.get("provider") or "").strip()
        anchor_ref = str(anchored.get("external_ref") or "").strip()
        anchor_receipt = anchored.get("receipt") if isinstance(anchored.get("receipt"), dict) else {}

    storage = get_storage_backend()
    created_at = _utc_now_iso()
    storage.execute(
        """
        INSERT INTO audit_independent_daily_checkpoints (
            tenant_id,
            checkpoint_id,
            date_utc,
            as_of_utc,
            ledger_root,
            ledger_size,
            prev_checkpoint_hash,
            checkpoint_hash,
            signature_algorithm,
            signature_value,
            signing_key_id,
            anchor_provider,
            anchor_ref,
            anchor_receipt_json,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, checkpoint_id) DO NOTHING
        """,
        (
            effective_tenant,
            checkpoint_id,
            normalized_date,
            str(payload.get("as_of_utc")),
            ledger_root,
            ledger_size,
            prev_checkpoint_hash or None,
            checkpoint_hash,
            signature.get("algorithm") or SIGNATURE_ALGORITHM,
            signature.get("value") or "",
            signature.get("key_id") or "",
            anchor_provider or None,
            anchor_ref or None,
            canonical_json(anchor_receipt),
            created_at,
        ),
    )
    saved = _load_checkpoint_row(tenant_id=effective_tenant, date_utc=normalized_date)
    if not saved:
        raise RuntimeError("failed to persist independent daily checkpoint")
    checkpoint = _row_to_checkpoint(saved)
    checkpoint["created"] = True
    return checkpoint


def verify_independent_daily_checkpoint(
    *,
    date_utc: str,
    tenant_id: Optional[str],
    require_anchor: bool = True,
    signing_key: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_date = _normalize_date_utc(date_utc)
    row = _load_checkpoint_row(tenant_id=effective_tenant, date_utc=normalized_date)
    if not row:
        return {
            "exists": False,
            "valid": False,
            "tenant_id": effective_tenant,
            "date_utc": normalized_date,
            "reason": "checkpoint not found",
        }
    checkpoint = _row_to_checkpoint(row)
    payload = checkpoint.get("payload") if isinstance(checkpoint.get("payload"), dict) else {}
    signature_obj = checkpoint.get("signature") if isinstance(checkpoint.get("signature"), dict) else {}

    expected_hash = _payload_hash(payload)
    hash_match = str(row.get("checkpoint_hash") or "") == expected_hash
    material = _signing_material(tenant_id=effective_tenant, signing_key=signing_key)
    expected_sig = _signature_for_payload(payload=payload, material=material).get("value")
    signature_match = hmac.compare_digest(str(expected_sig or ""), str(signature_obj.get("value") or ""))

    root = get_or_compute_transparency_root(date_utc=normalized_date, tenant_id=effective_tenant)
    root_hash_match = bool(root and str(root.get("root_hash") or "") == str(payload.get("ledger_root") or ""))
    leaf_count_match = bool(root and int(root.get("leaf_count") or 0) == int(payload.get("ledger_size") or 0))

    anchor = checkpoint.get("external_anchor") if isinstance(checkpoint.get("external_anchor"), dict) else {}
    anchor_present = bool(str(anchor.get("provider") or "").strip() and str(anchor.get("external_ref") or "").strip())

    valid = bool(hash_match and signature_match and root_hash_match and leaf_count_match and (anchor_present or not require_anchor))
    return {
        "exists": True,
        "valid": valid,
        "tenant_id": effective_tenant,
        "date_utc": normalized_date,
        "checkpoint_id": payload.get("checkpoint_id"),
        "hash_match": hash_match,
        "signature_valid": signature_match,
        "root_hash_match": root_hash_match,
        "leaf_count_match": leaf_count_match,
        "anchor_present": anchor_present,
        "require_anchor": bool(require_anchor),
        "checkpoint": checkpoint,
    }
