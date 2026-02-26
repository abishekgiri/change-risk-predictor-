from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from releasegate.integrations.jira.lock_store import compute_lock_chain_root
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import sha256_json


EMPTY_ROOT_HASH = hashlib.sha256(b"releasegate-empty-checkpoint").hexdigest()
DEFAULT_CADENCE = "daily"
SUPPORTED_CADENCES = {"daily", "weekly"}
SCHEMA_NAME = "checkpoint"
SCHEMA_VERSION = "checkpoint_v1"
CANONICALIZATION_VERSION = "releasegate-canonical-json-v1"
HASH_ALGORITHM = "sha256"
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_PERIOD_DAILY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PERIOD_WEEKLY_RE = re.compile(r"^\d{4}-W\d{2}$")


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


def _safe_segment(value: str, *, field_name: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{field_name} is empty")
    if "/" in raw or "\\" in raw or ".." in raw:
        raise ValueError(f"{field_name} contains unsupported path characters")
    if not _SEGMENT_RE.fullmatch(raw):
        raise ValueError(f"{field_name} contains unsupported characters")
    return raw


def _repo_dir_name(repo: str) -> str:
    raw = str(repo or "").strip()
    parts = raw.split("/")
    if len(parts) == 1:
        return _safe_segment(parts[0], field_name="repo")
    if len(parts) == 2:
        owner_safe = _safe_segment(parts[0], field_name="repo owner")
        name_safe = _safe_segment(parts[1], field_name="repo name")
        return f"{owner_safe}__{name_safe}"
    raise ValueError("repo must be a single slug or owner/repo format")


def _chain_dir_name(chain_id: str) -> str:
    normalized = str(chain_id or "").strip().replace(":", "__")
    return _safe_segment(normalized, field_name="chain_id")


def _safe_join_under_root(root: Path, *parts: str) -> Path:
    root_abs = root.resolve(strict=False)
    candidate = root_abs.joinpath(*parts).resolve(strict=False)
    if os.path.commonpath([str(root_abs), str(candidate)]) != str(root_abs):
        raise ValueError("Unsafe checkpoint path outside configured checkpoint directory")
    return candidate


def _validate_period_id(period_id: str, cadence: str) -> str:
    value = str(period_id or "").strip()
    if not value:
        raise ValueError("period_id is empty")
    if cadence == "daily":
        if not _PERIOD_DAILY_RE.fullmatch(value):
            raise ValueError("Invalid daily period_id format (expected YYYY-MM-DD)")
        return value
    if cadence == "weekly":
        if not _PERIOD_WEEKLY_RE.fullmatch(value):
            raise ValueError("Invalid weekly period_id format (expected YYYY-Www)")
        return value
    raise ValueError(f"Unsupported cadence `{cadence}`")


def _checkpoint_store_dir(store_dir: Optional[str] = None) -> Path:
    resolved = store_dir or os.getenv("RELEASEGATE_CHECKPOINT_STORE_DIR", "audit_bundles/checkpoints")
    path = Path(resolved).expanduser().resolve(strict=False)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _checkpoint_dir(
    repo: str,
    cadence: str,
    *,
    tenant_id: str,
    store_dir: Optional[str] = None,
) -> Path:
    root = _checkpoint_store_dir(store_dir)
    tenant_dir = _safe_segment(tenant_id, field_name="tenant_id")
    repo_dir = _repo_dir_name(repo)
    path = _safe_join_under_root(root, tenant_dir, repo_dir, cadence)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _lock_checkpoint_dir(
    chain_id: str,
    cadence: str,
    *,
    tenant_id: str,
    store_dir: Optional[str] = None,
) -> Path:
    root = _checkpoint_store_dir(store_dir)
    tenant_dir = _safe_segment(tenant_id, field_name="tenant_id")
    chain_dir = _chain_dir_name(chain_id)
    path = _safe_join_under_root(root, tenant_dir, "jira-lock", chain_dir, cadence)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _checkpoint_signing_material(
    signing_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, str]:
    if signing_key:
        return {"key": signing_key, "key_id": "manual"}

    env_key = os.getenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY", "").strip()
    if env_key:
        return {
            "key": env_key,
            "key_id": (os.getenv("RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID") or "env").strip(),
        }

    if tenant_id:
        try:
            from releasegate.security.checkpoint_keys import get_active_checkpoint_signing_key_record

            record = get_active_checkpoint_signing_key_record(tenant_id)
            if record and record.get("key"):
                return {
                    "key": str(record["key"]),
                    "key_id": str(record.get("key_id") or "tenant-active-key"),
                }
        except Exception:
            pass

    raise ValueError("Checkpoint signing key missing. Set RELEASEGATE_CHECKPOINT_SIGNING_KEY.")


def _checkpoint_path(
    repo: str,
    cadence: str,
    period_id: str,
    *,
    tenant_id: str,
    store_dir: Optional[str] = None,
) -> Path:
    path = _checkpoint_dir(repo, cadence, tenant_id=tenant_id, store_dir=store_dir)
    safe_period_id = _validate_period_id(period_id, cadence)
    return _safe_join_under_root(path, f"{safe_period_id}.json")


def _lock_checkpoint_path(
    chain_id: str,
    cadence: str,
    period_id: str,
    *,
    tenant_id: str,
    store_dir: Optional[str] = None,
) -> Path:
    path = _lock_checkpoint_dir(chain_id, cadence, tenant_id=tenant_id, store_dir=store_dir)
    safe_period_id = _validate_period_id(period_id, cadence)
    return _safe_join_under_root(path, f"{safe_period_id}.json")


def _load_rows(repo: str, pr: Optional[int] = None, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    query = """
        SELECT override_id, tenant_id, decision_id, repo, pr_number, issue_key, actor, reason,
               target_type, target_id, idempotency_key, previous_hash, event_hash, created_at,
               ttl_seconds, expires_at, requested_by, approved_by
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
    if row.get("ttl_seconds") is not None:
        payload["ttl_seconds"] = row["ttl_seconds"]
    if row.get("expires_at") is not None:
        payload["expires_at"] = row["expires_at"]
    if row.get("requested_by") is not None:
        payload["requested_by"] = row["requested_by"]
    if row.get("approved_by") is not None:
        payload["approved_by"] = row["approved_by"]
    return payload


def _checkpoint_id(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(
        f"{payload.get('tenant_id')}:{payload.get('repo')}:{payload.get('cadence')}:{payload.get('period_id')}:{payload.get('pr_number')}".encode(
            "utf-8"
        )
    ).hexdigest()[:32]


def _lock_checkpoint_id(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(
        f"{payload.get('tenant_id')}:{payload.get('chain_id')}:{payload.get('cadence')}:{payload.get('period_id')}".encode(
            "utf-8"
        )
    ).hexdigest()[:32]


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
    tip_override_id: Optional[str] = None

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
        tip_override_id = row.get("override_id")

    return {
        "valid_chain": True,
        "reason": None,
        "event_count": len(rows),
        "root_hash": rolling_root if rows else EMPTY_ROOT_HASH,
        "tip_event_hash": expected_prev if rows else "",
        "tip_override_id": tip_override_id,
        "first_event_at": first_event_at,
        "last_event_at": last_event_at,
        "tenant_id": effective_tenant,
    }


def _sign_payload(
    payload: Dict[str, Any],
    signing_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, str]:
    effective_tenant = tenant_id or payload.get("tenant_id")
    material = _checkpoint_signing_material(signing_key, tenant_id=effective_tenant)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "algorithm": "HMAC-SHA256",
        "value": hmac.new(material["key"].encode("utf-8"), canonical, hashlib.sha256).hexdigest(),
        "key_id": material.get("key_id") or "",
    }


def checkpoint_hash(payload: Dict[str, Any]) -> str:
    material = dict(payload or {})
    material.pop("checkpoint_hash", None)
    return f"sha256:{sha256_json(material)}"


def verify_checkpoint_signature(checkpoint: Dict[str, Any], signing_key: Optional[str] = None) -> bool:
    payload = checkpoint.get("payload")
    signature_obj = checkpoint.get("signature", {})
    signature = signature_obj.get("value")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False
    expected = _sign_payload(payload, signing_key=signing_key, tenant_id=payload.get("tenant_id")).get("value")
    return hmac.compare_digest(expected, signature)


def _record_checkpoint_metadata(checkpoint: Dict[str, Any], path: str) -> None:
    payload = checkpoint.get("payload", {})
    signature = checkpoint.get("signature", {})
    checkpoint_id = (
        checkpoint.get("ids", {}).get("checkpoint_id")
        or _checkpoint_id(payload)
    )

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


def _record_lock_checkpoint_metadata(checkpoint: Dict[str, Any], path: str) -> None:
    payload = checkpoint.get("payload", {})
    signature = checkpoint.get("signature", {})
    checkpoint_id = (
        checkpoint.get("ids", {}).get("checkpoint_id")
        or _lock_checkpoint_id(payload)
    )

    init_db()
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO audit_lock_checkpoints (
            tenant_id, checkpoint_id, chain_id, cadence, period_id, period_end, head_seq, head_hash, event_count,
            signature_algorithm, signature_value, path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, checkpoint_id) DO NOTHING
        """,
        (
            payload.get("tenant_id"),
            checkpoint_id,
            payload.get("chain_id"),
            payload.get("cadence"),
            payload.get("period_id"),
            payload.get("period_end"),
            int(payload.get("head_seq", 0)),
            payload.get("head_hash"),
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
    payload["checkpoint_hash"] = checkpoint_hash(payload)
    signature_obj = _sign_payload(payload, signing_key=signing_key, tenant_id=effective_tenant)
    checkpoint_id = _checkpoint_id(payload)
    checkpoint = {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "generated_at": payload.get("generated_at"),
        "tenant_id": effective_tenant,
        "ids": {
            "checkpoint_id": checkpoint_id,
            "decision_id": "",
            "proof_pack_id": "",
            "policy_bundle_hash": "",
            "repo": repo,
            "pr_number": pr,
            "period_id": period_id,
            "cadence": cadence,
        },
        "integrity": {
            "canonicalization": CANONICALIZATION_VERSION,
            "hash_alg": HASH_ALGORITHM,
            "input_hash": "",
            "policy_hash": "",
            "decision_hash": "",
            "replay_hash": "",
            "ledger": {
                "ledger_tip_hash": chain.get("tip_event_hash") or "",
                "ledger_record_id": chain.get("tip_override_id") or "",
            },
            "signatures": {
                "checkpoint_signature": signature_obj.get("value") or "",
                "signing_key_id": signature_obj.get("key_id") or "",
            },
        },
        "checkpoint_version": "v1",
        "payload": payload,
        "signature": signature_obj,
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
    dir_path = _checkpoint_dir(repo, cadence, tenant_id=effective_tenant, store_dir=store_dir)
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
            "schema_name": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
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
        "schema_name": checkpoint.get("schema_name", SCHEMA_NAME),
        "schema_version": checkpoint.get("schema_version", SCHEMA_VERSION),
        "generated_at": checkpoint.get("generated_at") or payload.get("generated_at"),
        "ids": checkpoint.get("ids", {}),
        "integrity": checkpoint.get("integrity", {}),
        "tenant_id": payload_tenant,
        "repo": payload_repo,
        "cadence": payload.get("cadence", cadence),
        "period_id": payload.get("period_id", period_id),
        "signature_valid": bool(signature_valid),
        "signature_error": signature_error,
        "checkpoint_hash_match": str(payload.get("checkpoint_hash") or "") == checkpoint_hash(payload),
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


def create_jira_lock_checkpoint(
    chain_id: str,
    *,
    cadence: str = DEFAULT_CADENCE,
    at: Optional[Any] = None,
    store_dir: Optional[str] = None,
    signing_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    cadence = _resolve_cadence(cadence)
    effective_tenant = resolve_tenant_id(tenant_id)
    generated_at = parse_utc_datetime(at) if at is not None else datetime.now(timezone.utc)
    period_id = period_id_for_timestamp(generated_at, cadence=cadence)

    chain = compute_lock_chain_root(
        tenant_id=effective_tenant,
        chain_id=chain_id,
        up_to=generated_at,
    )
    if not chain.get("valid_chain", False):
        raise ValueError(f"Cannot checkpoint invalid lock chain: {chain.get('reason')}")

    payload = {
        "tenant_id": effective_tenant,
        "chain_id": chain_id,
        "cadence": cadence,
        "period_id": period_id,
        "period_end": generated_at.isoformat(),
        "head_seq": int(chain.get("head_seq", 0)),
        "head_hash": chain.get("head_hash") or EMPTY_ROOT_HASH,
        "event_count": int(chain.get("event_count", 0)),
        "first_event_at": chain.get("first_event_at"),
        "last_event_at": chain.get("last_event_at"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    payload["checkpoint_hash"] = checkpoint_hash(payload)
    signature_obj = _sign_payload(payload, signing_key=signing_key, tenant_id=effective_tenant)
    checkpoint_id = _lock_checkpoint_id(payload)
    checkpoint = {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "generated_at": payload.get("generated_at"),
        "tenant_id": effective_tenant,
        "ids": {
            "checkpoint_id": checkpoint_id,
            "decision_id": "",
            "proof_pack_id": "",
            "policy_bundle_hash": "",
            "repo": "",
            "pr_number": None,
            "period_id": period_id,
            "cadence": cadence,
            "chain_id": chain_id,
        },
        "integrity": {
            "canonicalization": CANONICALIZATION_VERSION,
            "hash_alg": HASH_ALGORITHM,
            "input_hash": "",
            "policy_hash": "",
            "decision_hash": "",
            "replay_hash": "",
            "ledger": {
                "ledger_tip_hash": payload.get("head_hash") or "",
                "ledger_record_id": str(payload.get("head_seq") or ""),
            },
            "signatures": {
                "checkpoint_signature": signature_obj.get("value") or "",
                "signing_key_id": signature_obj.get("key_id") or "",
            },
        },
        "checkpoint_version": "v1",
        "payload": payload,
        "signature": signature_obj,
    }

    path = _lock_checkpoint_path(
        chain_id,
        cadence,
        period_id,
        tenant_id=effective_tenant,
        store_dir=store_dir,
    )
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        existing["path"] = str(path)
        existing["created"] = False
        _record_lock_checkpoint_metadata(existing, str(path))
        return existing

    path.write_text(json.dumps(checkpoint, indent=2, sort_keys=True), encoding="utf-8")
    checkpoint["path"] = str(path)
    checkpoint["created"] = True
    _record_lock_checkpoint_metadata(checkpoint, str(path))
    return checkpoint


def load_jira_lock_checkpoint(
    chain_id: str,
    *,
    cadence: str = DEFAULT_CADENCE,
    period_id: str,
    store_dir: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    cadence = _resolve_cadence(cadence)
    effective_tenant = resolve_tenant_id(tenant_id)
    path = _lock_checkpoint_path(chain_id, cadence, period_id, tenant_id=effective_tenant, store_dir=store_dir)
    if not path.exists():
        return None
    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    checkpoint["path"] = str(path)
    return checkpoint


def latest_jira_lock_checkpoint(
    chain_id: str,
    *,
    cadence: str = DEFAULT_CADENCE,
    store_dir: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    cadence = _resolve_cadence(cadence)
    effective_tenant = resolve_tenant_id(tenant_id)
    dir_path = _lock_checkpoint_dir(chain_id, cadence, tenant_id=effective_tenant, store_dir=store_dir)
    if not dir_path.exists():
        return None
    files = [p for p in dir_path.glob("*.json") if p.is_file()]
    if not files:
        return None
    latest = sorted(files)[-1]
    checkpoint = json.loads(latest.read_text(encoding="utf-8"))
    checkpoint["path"] = str(latest)
    return checkpoint


def verify_jira_lock_checkpoint(
    chain_id: str,
    *,
    cadence: str = DEFAULT_CADENCE,
    period_id: str,
    store_dir: Optional[str] = None,
    signing_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    checkpoint = load_jira_lock_checkpoint(
        chain_id=chain_id,
        cadence=cadence,
        period_id=period_id,
        store_dir=store_dir,
        tenant_id=effective_tenant,
    )
    if checkpoint is None:
        return {
            "exists": False,
            "valid": False,
            "schema_name": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "tenant_id": effective_tenant,
            "chain_id": chain_id,
            "cadence": cadence,
            "period_id": period_id,
            "reason": "checkpoint not found",
        }

    payload = checkpoint.get("payload", {})
    payload_tenant = payload.get("tenant_id") or effective_tenant
    payload_chain = payload.get("chain_id") or chain_id
    period_end = payload.get("period_end")

    signature_valid = False
    signature_error = None
    try:
        signature_valid = verify_checkpoint_signature(checkpoint, signing_key=signing_key)
    except ValueError as exc:
        signature_error = str(exc)

    chain = compute_lock_chain_root(
        tenant_id=payload_tenant,
        chain_id=payload_chain,
        up_to=period_end,
    )
    head_hash_match = str(chain.get("head_hash") or EMPTY_ROOT_HASH) == str(payload.get("head_hash") or EMPTY_ROOT_HASH)
    head_seq_match = int(chain.get("head_seq", -1)) == int(payload.get("head_seq", -2))
    event_count_match = int(chain.get("event_count", -1)) == int(payload.get("event_count", -2))

    valid = bool(
        signature_valid
        and chain.get("valid_chain")
        and head_hash_match
        and head_seq_match
        and event_count_match
    )
    result = {
        "exists": True,
        "valid": valid,
        "schema_name": checkpoint.get("schema_name", SCHEMA_NAME),
        "schema_version": checkpoint.get("schema_version", SCHEMA_VERSION),
        "generated_at": checkpoint.get("generated_at") or payload.get("generated_at"),
        "ids": checkpoint.get("ids", {}),
        "integrity": checkpoint.get("integrity", {}),
        "tenant_id": payload_tenant,
        "chain_id": payload_chain,
        "cadence": payload.get("cadence", cadence),
        "period_id": payload.get("period_id", period_id),
        "signature_valid": bool(signature_valid),
        "signature_error": signature_error,
        "checkpoint_hash_match": str(payload.get("checkpoint_hash") or "") == checkpoint_hash(payload),
        "chain_valid": bool(chain.get("valid_chain")),
        "head_hash_match": bool(head_hash_match),
        "head_seq_match": bool(head_seq_match),
        "event_count_match": bool(event_count_match),
        "checkpoint_head_hash": payload.get("head_hash"),
        "computed_head_hash": chain.get("head_hash"),
        "checkpoint_head_seq": payload.get("head_seq"),
        "computed_head_seq": chain.get("head_seq"),
        "checkpoint_event_count": payload.get("event_count"),
        "computed_event_count": chain.get("event_count"),
        "period_end": period_end,
        "path": checkpoint.get("path"),
    }
    if not chain.get("valid_chain"):
        result["chain_reason"] = chain.get("reason")
    return result
