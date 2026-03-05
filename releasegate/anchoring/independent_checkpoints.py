from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import requests

from releasegate.anchoring.roots import anchor_transparency_root
from releasegate.audit.transparency import get_or_compute_transparency_root
from releasegate.attestation.crypto import load_public_keys_map, parse_public_key, sign_message_for_tenant
from releasegate.config import get_anchor_provider_name
from releasegate.security.checkpoint_keys import get_active_checkpoint_signing_key_record
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


SCHEMA_NAME = "independent_daily_checkpoint"
SCHEMA_VERSION = "v1"
CANONICALIZATION = "releasegate-canonical-json-v1"
HASH_ALGORITHM = "sha256"
LOCAL_PROVIDERS = {"", "local", "local_transparency", "transparency"}


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


def _is_strict_anchor_mode() -> bool:
    raw = str(os.getenv("RELEASEGATE_ANCHOR_STRICT", "false") or "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _resolve_provider(provider_name: Optional[str]) -> str:
    return str(provider_name or get_anchor_provider_name() or "").strip().lower()


def _resolve_signature_algorithm(*, strict_mode: bool) -> str:
    fallback = "ed25519" if strict_mode else "hmac-sha256"
    value = str(os.getenv("RELEASEGATE_ANCHOR_SIG_ALG", fallback) or fallback).strip().lower()
    if value in {"hmac", "hmac_sha256", "hmac-sha256"}:
        return "hmac-sha256"
    if value in {"ed25519", "eddsa"}:
        return "ed25519"
    raise ValueError("Unsupported RELEASEGATE_ANCHOR_SIG_ALG (expected hmac-sha256 or ed25519)")


def _checkpoint_signing_material(*, tenant_id: str, signing_key: Optional[str]) -> Dict[str, str]:
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


def _canonical_payload_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _payload_hash(payload: Dict[str, Any]) -> str:
    return f"sha256:{sha256_json(payload)}"


def _checkpoint_id(*, tenant_id: str, date_utc: str, ledger_root: str) -> str:
    material = f"{tenant_id}:{date_utc}:{ledger_root}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _sign_payload(
    *,
    tenant_id: str,
    payload: Dict[str, Any],
    signature_algorithm: str,
    signing_key: Optional[str],
) -> Dict[str, str]:
    canonical = _canonical_payload_bytes(payload)
    if signature_algorithm == "hmac-sha256":
        material = _checkpoint_signing_material(tenant_id=tenant_id, signing_key=signing_key)
        return {
            "algorithm": "hmac-sha256",
            "value": hmac.new(str(material["key"]).encode("utf-8"), canonical, hashlib.sha256).hexdigest(),
            "key_id": str(material.get("key_id") or ""),
            "public_key": "",
        }

    if signature_algorithm != "ed25519":
        raise ValueError("Unsupported checkpoint signature algorithm")

    signature_bytes, key_id = sign_message_for_tenant(
        tenant_id,
        canonical,
        purpose="independent_daily_checkpoint_signing",
        actor="system:independent_checkpoint",
    )

    key_map = load_public_keys_map(tenant_id=tenant_id, include_verify_only=True, include_revoked=True)
    if not key_map:
        key_map = load_public_keys_map(tenant_id=None, include_verify_only=True, include_revoked=True)
    public_key = str((key_map or {}).get(str(key_id) or "") or "").strip()
    if not public_key:
        raise ValueError("Unable to resolve public key for checkpoint signature")

    return {
        "algorithm": "ed25519",
        "value": base64.b64encode(signature_bytes).decode("ascii"),
        "key_id": str(key_id or ""),
        "public_key": public_key,
    }


def _verify_payload_signature(
    *,
    tenant_id: str,
    payload: Dict[str, Any],
    signature_obj: Dict[str, Any],
    signing_key: Optional[str],
) -> Tuple[bool, str]:
    algorithm = str(signature_obj.get("algorithm") or "").strip().lower()
    canonical = _canonical_payload_bytes(payload)
    signature_value = str(signature_obj.get("value") or "").strip()

    if algorithm in {"hmac", "hmac-sha256", "hmac_sha256"}:
        try:
            material = _checkpoint_signing_material(tenant_id=tenant_id, signing_key=signing_key)
        except Exception:
            return False, "hmac_material_unavailable"
        expected = hmac.new(str(material["key"]).encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_value), "ok"

    if algorithm != "ed25519":
        return False, "unsupported_signature_algorithm"

    key_id = str(signature_obj.get("key_id") or "").strip()
    public_key_raw = str(signature_obj.get("public_key") or "").strip()
    if not public_key_raw and key_id:
        key_map = load_public_keys_map(tenant_id=tenant_id, include_verify_only=True, include_revoked=True)
        public_key_raw = str((key_map or {}).get(key_id) or "").strip()
    if not public_key_raw and key_id:
        key_map = load_public_keys_map(tenant_id=None, include_verify_only=True, include_revoked=True)
        public_key_raw = str((key_map or {}).get(key_id) or "").strip()
    if not public_key_raw:
        return False, "missing_public_key"

    try:
        public_key = parse_public_key(public_key_raw)
        signature = base64.b64decode(signature_value.encode("ascii"), validate=True)
        public_key.verify(signature, canonical)
        return True, "ok"
    except Exception:
        return False, "signature_mismatch"


def _parse_json(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
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
    anchor_receipt = _parse_json(row.get("anchor_receipt_json"))
    signature = {
        "algorithm": str(row.get("signature_algorithm") or "").strip().lower() or "hmac-sha256",
        "value": row.get("signature_value") or "",
        "key_id": row.get("signing_key_id") or "",
        "public_key": str(anchor_receipt.get("public_key") or "").strip(),
    }
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
                "algorithm": signature.get("algorithm") or "",
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


def _load_checkpoint_row_by_id(*, tenant_id: str, checkpoint_id: str) -> Optional[Dict[str, Any]]:
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
        WHERE tenant_id = ? AND checkpoint_id = ?
        LIMIT 1
        """,
        (tenant_id, checkpoint_id),
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


def _http_timeout_seconds() -> float:
    raw = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_TIMEOUT_SECONDS") or "5").strip()
    try:
        return max(0.1, float(raw))
    except Exception:
        return 5.0


def _http_headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_TOKEN") or "").strip()
    if token:
        header_name = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_AUTH_HEADER") or "Authorization").strip()
        if header_name.lower() == "authorization" and not token.lower().startswith("bearer "):
            headers[header_name] = f"Bearer {token}"
        else:
            headers[header_name] = token
    return headers


def _publish_checkpoint_to_external(
    *,
    provider: str,
    external_ref: str,
    checkpoint_document: Dict[str, Any],
) -> Dict[str, Any]:
    if provider in LOCAL_PROVIDERS:
        return {
            "provider": provider or "local_transparency",
            "external_ref": external_ref,
            "fetch_url": "",
            "published": False,
        }

    if provider != "http_transparency":
        return {
            "provider": provider,
            "external_ref": external_ref,
            "fetch_url": "",
            "published": False,
        }

    publish_url = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_CHECKPOINT_PUBLISH_URL") or "").strip()
    if not publish_url:
        raise ValueError("RELEASEGATE_ANCHOR_HTTP_CHECKPOINT_PUBLISH_URL is required for http_transparency")

    body = {
        "external_ref": external_ref,
        "checkpoint": checkpoint_document,
    }
    response = requests.post(
        publish_url,
        json=body,
        headers=_http_headers(),
        timeout=_http_timeout_seconds(),
    )
    if response.status_code not in {200, 201, 202}:
        raise ValueError(f"external checkpoint publish failed with status {response.status_code}")

    response_body: Dict[str, Any] = {}
    try:
        decoded = response.json()
        if isinstance(decoded, dict):
            response_body = decoded
    except Exception:
        response_body = {}

    resolved_ref = str(
        response_body.get("external_ref")
        or response_body.get("checkpoint_ref")
        or response_body.get("id")
        or external_ref
    ).strip()
    fetch_url = str(response_body.get("fetch_url") or "").strip()
    return {
        "provider": provider,
        "external_ref": resolved_ref,
        "fetch_url": fetch_url,
        "published": True,
        "response": response_body,
    }


def _fetch_external_checkpoint_payload(
    *,
    provider: str,
    external_ref: str,
    receipt: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[str], float]:
    started = time.perf_counter()

    if provider in LOCAL_PROVIDERS:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return None, "local_provider_not_independent", elapsed_ms

    if provider != "http_transparency":
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return None, "external_fetch_not_supported_for_provider", elapsed_ms

    fetch_url = ""
    publish_meta = receipt.get("checkpoint_publish") if isinstance(receipt.get("checkpoint_publish"), dict) else {}
    if isinstance(publish_meta, dict):
        fetch_url = str(publish_meta.get("fetch_url") or "").strip()
    if not fetch_url:
        fetch_url = str(os.getenv("RELEASEGATE_ANCHOR_HTTP_CHECKPOINT_FETCH_URL") or "").strip()
    if not fetch_url:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return None, "external_fetch_url_missing", elapsed_ms

    if "{external_ref}" in fetch_url:
        url = fetch_url.replace("{external_ref}", external_ref)
        response = requests.get(url, headers=_http_headers(), timeout=_http_timeout_seconds())
    else:
        response = requests.get(
            fetch_url,
            params={"ref": external_ref},
            headers=_http_headers(),
            timeout=_http_timeout_seconds(),
        )

    if response.status_code not in {200}:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return None, f"external_fetch_http_{response.status_code}", elapsed_ms

    try:
        body = response.json()
    except Exception:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return None, "external_fetch_invalid_json", elapsed_ms
    if not isinstance(body, dict):
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return None, "external_fetch_invalid_payload", elapsed_ms

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return body, None, elapsed_ms


def _evaluate_external_anchor_match(
    *,
    expected_payload: Dict[str, Any],
    expected_checkpoint_hash: str,
    provider: str,
    external_ref: str,
    receipt: Dict[str, Any],
) -> Dict[str, Any]:
    fetched, fetch_error, latency_ms = _fetch_external_checkpoint_payload(
        provider=provider,
        external_ref=external_ref,
        receipt=receipt,
    )
    if fetched is None:
        return {
            "valid": False,
            "reason": fetch_error or "external_fetch_failed",
            "latency_ms": round(latency_ms, 3),
            "fetched": None,
        }

    checkpoint_doc = fetched.get("checkpoint") if isinstance(fetched.get("checkpoint"), dict) else fetched
    payload = checkpoint_doc.get("payload") if isinstance(checkpoint_doc.get("payload"), dict) else {}
    integrity = checkpoint_doc.get("integrity") if isinstance(checkpoint_doc.get("integrity"), dict) else {}

    external_hash = str(integrity.get("checkpoint_hash") or fetched.get("checkpoint_hash") or "").strip()
    if not external_hash and payload:
        external_hash = _payload_hash(payload)

    external_root = str(payload.get("ledger_root") or fetched.get("root_hash") or "").strip()
    expected_root = str(expected_payload.get("ledger_root") or "").strip()

    hash_match = bool(external_hash and external_hash == expected_checkpoint_hash)
    root_match = bool(external_root and expected_root and external_root == expected_root)

    return {
        "valid": bool(hash_match or root_match),
        "reason": "ok" if (hash_match or root_match) else "external_anchor_mismatch",
        "latency_ms": round(latency_ms, 3),
        "hash_match": hash_match,
        "root_match": root_match,
        "fetched": {
            "checkpoint_hash": external_hash,
            "ledger_root": external_root,
        },
    }


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


def get_independent_daily_checkpoint_by_id(
    *,
    checkpoint_id: str,
    tenant_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_checkpoint_id = str(checkpoint_id or "").strip()
    if not normalized_checkpoint_id:
        return None
    row = _load_checkpoint_row_by_id(
        tenant_id=effective_tenant,
        checkpoint_id=normalized_checkpoint_id,
    )
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

    strict_mode = _is_strict_anchor_mode()
    provider = _resolve_provider(provider_name)
    if publish_anchor and strict_mode and provider in LOCAL_PROVIDERS:
        raise ValueError("INDEPENDENCE_REQUIRED: strict anchoring requires non-local provider")

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

    signature_algorithm = _resolve_signature_algorithm(strict_mode=strict_mode)
    if strict_mode and signature_algorithm != "ed25519":
        raise ValueError("INDEPENDENCE_REQUIRED: strict anchoring requires ed25519 signatures")

    signature = _sign_payload(
        tenant_id=effective_tenant,
        payload=payload,
        signature_algorithm=signature_algorithm,
        signing_key=signing_key,
    )
    checkpoint_hash = _payload_hash(payload)

    checkpoint_document = {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "payload": payload,
        "integrity": {
            "canonicalization": CANONICALIZATION,
            "hash_alg": HASH_ALGORITHM,
            "checkpoint_hash": checkpoint_hash,
        },
        "signature": signature,
    }

    anchor_provider = ""
    anchor_ref = ""
    anchor_receipt: Dict[str, Any] = {}
    if publish_anchor:
        anchored = anchor_transparency_root(
            date_utc=normalized_date,
            tenant_id=effective_tenant,
            provider_name=provider,
        )
        if not anchored:
            raise ValueError("external anchor publish failed")
        root_anchor_ref = str(anchored.get("external_ref") or anchored.get("anchor_id") or "").strip()
        publish_receipt = _publish_checkpoint_to_external(
            provider=provider,
            external_ref=root_anchor_ref,
            checkpoint_document=checkpoint_document,
        )
        anchor_provider = provider
        anchor_ref = str(publish_receipt.get("external_ref") or root_anchor_ref).strip()
        anchor_receipt = {
            "public_key": signature.get("public_key") or "",
            "root_anchor": anchored,
            "checkpoint_publish": publish_receipt,
        }
    else:
        anchor_receipt = {
            "public_key": signature.get("public_key") or "",
        }

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
            signature.get("algorithm") or "",
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
    strict_mode = _is_strict_anchor_mode()
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
    signature_valid, signature_reason = _verify_payload_signature(
        tenant_id=effective_tenant,
        payload=payload,
        signature_obj=signature_obj,
        signing_key=signing_key,
    )

    root = get_or_compute_transparency_root(date_utc=normalized_date, tenant_id=effective_tenant)
    root_hash_match = bool(root and str(root.get("root_hash") or "") == str(payload.get("ledger_root") or ""))
    leaf_count_match = bool(root and int(root.get("leaf_count") or 0) == int(payload.get("ledger_size") or 0))

    anchor = checkpoint.get("external_anchor") if isinstance(checkpoint.get("external_anchor"), dict) else {}
    anchor_provider = str(anchor.get("provider") or "").strip().lower()
    anchor_ref = str(anchor.get("external_ref") or "").strip()
    anchor_receipt = anchor.get("receipt") if isinstance(anchor.get("receipt"), dict) else {}
    anchor_present = bool(anchor_provider and anchor_ref)

    if strict_mode and require_anchor and anchor_provider in LOCAL_PROVIDERS:
        return {
            "exists": True,
            "valid": False,
            "tenant_id": effective_tenant,
            "date_utc": normalized_date,
            "checkpoint_id": payload.get("checkpoint_id"),
            "reason": "INDEPENDENCE_REQUIRED",
            "hash_match": hash_match,
            "signature_valid": signature_valid,
            "signature_reason": signature_reason,
            "root_hash_match": root_hash_match,
            "leaf_count_match": leaf_count_match,
            "anchor_present": anchor_present,
            "external_anchor_verified": False,
            "checkpoint": checkpoint,
        }

    external_report = {
        "valid": False,
        "reason": "anchor_not_required",
        "latency_ms": 0.0,
    }
    if require_anchor and anchor_present:
        if anchor_provider in LOCAL_PROVIDERS and not strict_mode:
            external_report = {
                "valid": True,
                "reason": "local_provider_not_independent",
                "latency_ms": 0.0,
                "fetched": None,
            }
        else:
            external_report = _evaluate_external_anchor_match(
                expected_payload=payload,
                expected_checkpoint_hash=expected_hash,
                provider=anchor_provider,
                external_ref=anchor_ref,
                receipt=anchor_receipt,
            )
    elif require_anchor and not anchor_present:
        external_report = {
            "valid": False,
            "reason": "anchor_missing",
            "latency_ms": 0.0,
        }

    external_valid = bool(external_report.get("valid")) if require_anchor else True

    valid = bool(
        hash_match
        and signature_valid
        and root_hash_match
        and leaf_count_match
        and external_valid
    )
    return {
        "exists": True,
        "valid": valid,
        "tenant_id": effective_tenant,
        "date_utc": normalized_date,
        "checkpoint_id": payload.get("checkpoint_id"),
        "hash_match": hash_match,
        "signature_valid": signature_valid,
        "signature_reason": signature_reason,
        "root_hash_match": root_hash_match,
        "leaf_count_match": leaf_count_match,
        "anchor_present": anchor_present,
        "require_anchor": bool(require_anchor),
        "strict_mode": strict_mode,
        "external_anchor_verified": bool(external_report.get("valid")),
        "external_anchor_reason": str(external_report.get("reason") or ""),
        "external_anchor_latency_ms": float(external_report.get("latency_ms") or 0.0),
        "external_anchor_fetch": external_report.get("fetched"),
        "checkpoint": checkpoint,
    }
