from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


EMPTY_ROOT_HASH = hashlib.sha256(b"releasegate-empty-checkpoint").hexdigest()
DEFAULT_CADENCE = "daily"
SUPPORTED_CADENCES = {"daily", "weekly"}


def parse_utc_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value or "").strip()
        if not raw:
            raise ValueError("timestamp is empty")
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _resolve_cadence(cadence: str) -> str:
    normalized = (cadence or DEFAULT_CADENCE).strip().lower()
    if normalized not in SUPPORTED_CADENCES:
        raise ValueError(f"Unsupported cadence `{cadence}` (expected one of {sorted(SUPPORTED_CADENCES)})")
    return normalized


def period_id_for_timestamp(timestamp: Any, cadence: str = DEFAULT_CADENCE) -> str:
    dt = parse_utc_datetime(timestamp)
    cadence = _resolve_cadence(cadence)
    if cadence == "daily":
        return dt.strftime("%Y-%m-%d")
    iso = dt.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


def _sanitize_path_part(value: str) -> str:
    return value.replace("/", "__").replace("..", "_")


def _checkpoint_store_dir(store_dir: Optional[str] = None) -> Path:
    resolved = store_dir or os.getenv("RELEASEGATE_CHECKPOINT_STORE_DIR", "audit_bundles/checkpoints")
    path = Path(resolved)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _checkpoint_signing_key(signing_key: Optional[str] = None) -> bytes:
    key = signing_key or os.getenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "")
    if not key:
        raise ValueError("Checkpoint signing key missing. Set RELEASEGATE_CHECKPOINT_SIGNING_KEY.")
    return key.encode("utf-8")


def _checkpoint_path(
    repo: str,
    cadence: str,
    period_id: str,
    *,
    tenant_id: str,
    store_dir: Optional[str] = None,
) -> Path:
    root = _checkpoint_store_dir(store_dir)
    tenant_dir = _sanitize_path_part(tenant_id)
    repo_dir = _sanitize_path_part(repo)
    path = root / tenant_dir / repo_dir / cadence
    path.mkdir(parents=True, exist_ok=True)
    return path / f"{period_id}.json"


def _load_rows(repo: str, pr: Optional[int] = None, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    query = """
        SELECT override_id, tenant_id, decision_id, repo, pr_number, issue_key, actor, reason, target_type, target_id, idempotency_key, previous_hash, event_hash, created_at
        FROM audit_overrides
        WHERE tenant_id = ? AND repo = ?
    """
    params: List[Any] = [effective_tenant, repo]
    if pr is not None:
        query += " AND pr_number = ?"
        params.append(pr)
    query += " ORDER BY created_at ASC"
    return storage.fetchall(query, params)


def _event_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "tenant_id": row["tenant_id"],
        "repo": row["repo"],
        "pr_number": row["pr_number"],
        "issue_key": row["issue_key"],
        "decision_id": row["decision_id"],
        "actor": row["actor"],
        "reason": row["reason"],
        "previous_hash": row["previous_hash"],
        "created_at": row["created_at"],
    }
    if row.get("target_type") is not None:
        payload["target_type"] = row["target_type"]
    if row.get("target_id") is not None:
        payload["target_id"] = row["target_id"]
    if row.get("idempotency_key") is not None:
        payload["idempotency_key"] = row["idempotency_key"]
    return payload


def compute_override_chain_root(
    repo: str,
    *,
    pr: Optional[int] = None,
    up_to: Optional[Any] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    rows = _load_rows(repo=repo, pr=pr, tenant_id=effective_tenant)
    cutoff = parse_utc_datetime(up_to) if up_to is not None else None
    if cutoff is not None:
        rows = [r for r in rows if parse_utc_datetime(r["created_at"]) <= cutoff]

    expected_prev = "0" * 64
    rolling_root = expected_prev
    first_event_at: Optional[str] = None
    last_event_at: Optional[str] = None

    for idx, row in enumerate(rows):
        previous_hash = row.get("previous_hash") or ""
        if previous_hash != expected_prev:
            return {
                "valid_chain": False,
                "reason": "previous_hash mismatch",
                "at_index": idx,
                "override_id": row.get("override_id"),
                "event_count": len(rows),
                "root_hash": EMPTY_ROOT_HASH,
                "first_event_at": first_event_at,
                "last_event_at": last_event_at,
                "tenant_id": effective_tenant,
            }

        payload = _event_payload(row)
        expected_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        if expected_hash != row.get("event_hash"):
            return {
                "valid_chain": False,
                "reason": "event_hash mismatch",
                "at_index": idx,
                "override_id": row.get("override_id"),
                "event_count": len(rows),
                "root_hash": EMPTY_ROOT_HASH,
                "first_event_at": first_event_at,
                "last_event_at": last_event_at,
                "tenant_id": effective_tenant,
            }

        if first_event_at is None:
            first_event_at = row.get("created_at")
        last_event_at = row.get("created_at")
        rolling_root = hashlib.sha256(f"{rolling_root}:{row.get('event_hash')}".encode("utf-8")).hexdigest()
        expected_prev = row.get("event_hash") or ""

    return {
        "valid_chain": True,
        "reason": None,
        "event_count": len(rows),
        "root_hash": rolling_root if rows else EMPTY_ROOT_HASH,
        "first_event_at": first_event_at,
        "last_event_at": last_event_at,
        "tenant_id": effective_tenant,
    }


def _sign_payload(payload: Dict[str, Any], signing_key: Optional[str] = None) -> str:
    key = _checkpoint_signing_key(signing_key)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def verify_checkpoint_signature(checkpoint: Dict[str, Any], signing_key: Optional[str] = None) -> bool:
    payload = checkpoint.get("payload")
    signature = checkpoint.get("signature", {}).get("value")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False
    expected = _sign_payload(payload, signing_key=signing_key)
    return hmac.compare_digest(expected, signature)


def _record_checkpoint_metadata(checkpoint: Dict[str, Any], path: str) -> None:
    payload = checkpoint.get("payload", {})
    signature = checkpoint.get("signature", {})
    checkpoint_id = hashlib.sha256(
        f"{payload.get('tenant_id')}:{payload.get('repo')}:{payload.get('cadence')}:{payload.get('period_id')}:{payload.get('pr_number')}".encode(
            "utf-8"
        )
    ).hexdigest()[:32]

    init_db()
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO audit_checkpoints (
            checkpoint_id, tenant_id, repo, pr_number, cadence, period_id, period_end, root_hash, event_count,
            signature_algorithm, signature_value, path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, checkpoint_id) DO NOTHING
        """,
        (
            checkpoint_id,
            payload.get("tenant_id"),
            payload.get("repo"),
            payload.get("pr_number"),
            payload.get("cadence"),
            payload.get("period_id"),
            payload.get("period_end"),
            payload.get("root_hash"),
            int(payload.get("event_count", 0)),
            signature.get("algorithm") or "HMAC-SHA256",
            signature.get("value") or "",
            path,
            payload.get("generated_at") or datetime.now(timezone.utc).isoformat(),
        ),
    )


def create_override_checkpoint(
    repo: str,
    *,
    cadence: str = DEFAULT_CADENCE,
    pr: Optional[int] = None,
    at: Optional[Any] = None,
    store_dir: Optional[str] = None,
    signing_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    cadence = _resolve_cadence(cadence)
    effective_tenant = resolve_tenant_id(tenant_id)
    generated_at = parse_utc_datetime(at) if at is not None else datetime.now(timezone.utc)
    period_id = period_id_for_timestamp(generated_at, cadence=cadence)

    chain = compute_override_chain_root(repo=repo, pr=pr, up_to=generated_at, tenant_id=effective_tenant)
    if not chain.get("valid_chain", False):
        raise ValueError(f"Cannot checkpoint invalid chain: {chain.get('reason')}")

    payload = {
        "tenant_id": effective_tenant,
        "repo": repo,
        "pr_number": pr,
        "cadence": cadence,
        "period_id": period_id,
        "period_end": generated_at.isoformat(),
        "root_hash": chain.get("root_hash"),
        "event_count": int(chain.get("event_count", 0)),
        "first_event_at": chain.get("first_event_at"),
        "last_event_at": chain.get("last_event_at"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    signature_value = _sign_payload(payload, signing_key=signing_key)
    checkpoint = {
        "checkpoint_version": "v1",
        "payload": payload,
        "signature": {
            "algorithm": "HMAC-SHA256",
            "value": signature_value,
        },
    }

    path = _checkpoint_path(
        repo,
        cadence,
        period_id,
        tenant_id=effective_tenant,
        store_dir=store_dir,
    )
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        existing["path"] = str(path)
        existing["created"] = False
        _record_checkpoint_metadata(existing, str(path))
        return existing

    path.write_text(json.dumps(checkpoint, indent=2, sort_keys=True), encoding="utf-8")
    checkpoint["path"] = str(path)
    checkpoint["created"] = True
    _record_checkpoint_metadata(checkpoint, str(path))
    return checkpoint


def load_override_checkpoint(
    repo: str,
    *,
    cadence: str = DEFAULT_CADENCE,
    period_id: str,
    store_dir: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    cadence = _resolve_cadence(cadence)
    effective_tenant = resolve_tenant_id(tenant_id)
    path = _checkpoint_path(repo, cadence, period_id, tenant_id=effective_tenant, store_dir=store_dir)
    if not path.exists():
        return None
    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    checkpoint["path"] = str(path)
    return checkpoint


def latest_override_checkpoint(
    repo: str,
    *,
    cadence: str = DEFAULT_CADENCE,
    store_dir: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    cadence = _resolve_cadence(cadence)
    effective_tenant = resolve_tenant_id(tenant_id)
    dir_path = _checkpoint_path(repo, cadence, "tmp", tenant_id=effective_tenant, store_dir=store_dir).parent
    if not dir_path.exists():
        return None
    files = [p for p in dir_path.glob("*.json") if p.is_file()]
    if not files:
        return None
    latest = sorted(files)[-1]
    checkpoint = json.loads(latest.read_text(encoding="utf-8"))
    checkpoint["path"] = str(latest)
    return checkpoint


def verify_override_checkpoint(
    repo: str,
    *,
    cadence: str = DEFAULT_CADENCE,
    period_id: str,
    pr: Optional[int] = None,
    store_dir: Optional[str] = None,
    signing_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    checkpoint = load_override_checkpoint(
        repo=repo,
        cadence=cadence,
        period_id=period_id,
        store_dir=store_dir,
        tenant_id=effective_tenant,
    )
    if checkpoint is None:
        return {
            "exists": False,
            "valid": False,
            "tenant_id": effective_tenant,
            "repo": repo,
            "cadence": cadence,
            "period_id": period_id,
            "reason": "checkpoint not found",
        }

    payload = checkpoint.get("payload", {})
    payload_tenant = payload.get("tenant_id") or effective_tenant
    payload_repo = payload.get("repo") or repo
    payload_pr = payload.get("pr_number") if pr is None else pr
    period_end = payload.get("period_end")

    signature_valid = False
    signature_error = None
    try:
        signature_valid = verify_checkpoint_signature(checkpoint, signing_key=signing_key)
    except ValueError as exc:
        signature_error = str(exc)

    chain = compute_override_chain_root(
        repo=payload_repo,
        pr=payload_pr,
        up_to=period_end,
        tenant_id=payload_tenant,
    )
    root_hash_match = chain.get("root_hash") == payload.get("root_hash")
    event_count_match = int(chain.get("event_count", -1)) == int(payload.get("event_count", -2))

    valid = bool(signature_valid and chain.get("valid_chain") and root_hash_match and event_count_match)
    result = {
        "exists": True,
        "valid": valid,
        "tenant_id": payload_tenant,
        "repo": payload_repo,
        "cadence": payload.get("cadence", cadence),
        "period_id": payload.get("period_id", period_id),
        "signature_valid": bool(signature_valid),
        "signature_error": signature_error,
        "chain_valid": bool(chain.get("valid_chain")),
        "root_hash_match": bool(root_hash_match),
        "event_count_match": bool(event_count_match),
        "checkpoint_root_hash": payload.get("root_hash"),
        "computed_root_hash": chain.get("root_hash"),
        "checkpoint_event_count": payload.get("event_count"),
        "computed_event_count": chain.get("event_count"),
        "period_end": period_end,
        "path": checkpoint.get("path"),
    }
    if not chain.get("valid_chain"):
        result["chain_reason"] = chain.get("reason")
        result["override_id"] = chain.get("override_id")
    return result
