from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


SNAPSHOT_SCHEMA_VERSION = "resolved_policy_snapshot_v1"
DEFAULT_COMPILER_VERSION = "releasegate-policy-compiler-v1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalise_reason_codes(reason_codes: Optional[Sequence[str]]) -> List[str]:
    values = sorted({str(code or "").strip() for code in (reason_codes or []) if str(code or "").strip()})
    return values


def _normalise_json_object(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return json.loads(canonical_json(value))


def _snapshot_hash_material(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": snapshot.get("schema_version") or SNAPSHOT_SCHEMA_VERSION,
        "compiler_version": snapshot.get("compiler_version") or DEFAULT_COMPILER_VERSION,
        "policy_id": snapshot.get("policy_id") or "releasegate",
        "policy_version": snapshot.get("policy_version") or "1",
        "resolution_inputs": snapshot.get("resolution_inputs") or {},
        "resolved_policy": snapshot.get("resolved_policy") or {},
    }


def compute_snapshot_policy_hash(snapshot: Dict[str, Any]) -> str:
    digest = sha256_json(_snapshot_hash_material(snapshot))
    return f"sha256:{digest}"


def build_resolved_policy_snapshot(
    *,
    policy_id: str,
    policy_version: str,
    resolution_inputs: Optional[Dict[str, Any]],
    resolved_policy: Optional[Dict[str, Any]],
    compiler_version: str = DEFAULT_COMPILER_VERSION,
    schema_version: str = SNAPSHOT_SCHEMA_VERSION,
) -> Dict[str, Any]:
    snapshot = {
        "schema_version": str(schema_version or SNAPSHOT_SCHEMA_VERSION),
        "compiler_version": str(compiler_version or DEFAULT_COMPILER_VERSION),
        "policy_id": str(policy_id or "releasegate"),
        "policy_version": str(policy_version or "1"),
        "resolution_inputs": _normalise_json_object(resolution_inputs),
        "resolved_policy": _normalise_json_object(resolved_policy),
    }
    snapshot["policy_hash"] = compute_snapshot_policy_hash(snapshot)
    return snapshot


def store_resolved_policy_snapshot(
    *,
    tenant_id: Optional[str],
    snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    canonical_snapshot = json.loads(canonical_json(snapshot))
    policy_hash = str(canonical_snapshot.get("policy_hash") or compute_snapshot_policy_hash(canonical_snapshot))
    canonical_snapshot["policy_hash"] = policy_hash

    existing = storage.fetchone(
        """
        SELECT snapshot_id, policy_hash, snapshot_json, schema_version, compiler_version, created_at
        FROM policy_resolved_snapshots
        WHERE tenant_id = ? AND policy_hash = ?
        LIMIT 1
        """,
        (effective_tenant, policy_hash),
    )
    if existing:
        snapshot_json = existing.get("snapshot_json")
        try:
            parsed_snapshot = json.loads(snapshot_json) if isinstance(snapshot_json, str) else (snapshot_json or {})
        except Exception:
            parsed_snapshot = {}
        return {
            "tenant_id": effective_tenant,
            "snapshot_id": existing.get("snapshot_id"),
            "policy_hash": existing.get("policy_hash"),
            "snapshot": parsed_snapshot,
            "schema_version": existing.get("schema_version"),
            "compiler_version": existing.get("compiler_version"),
            "created_at": existing.get("created_at"),
            "deduped": True,
        }

    snapshot_id = str(uuid.uuid4())
    created_at = _utc_now()
    storage.execute(
        """
        INSERT INTO policy_resolved_snapshots (
            tenant_id, snapshot_id, policy_hash, snapshot_json, schema_version, compiler_version, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            snapshot_id,
            policy_hash,
            canonical_json(canonical_snapshot),
            str(canonical_snapshot.get("schema_version") or SNAPSHOT_SCHEMA_VERSION),
            str(canonical_snapshot.get("compiler_version") or DEFAULT_COMPILER_VERSION),
            created_at,
        ),
    )
    return {
        "tenant_id": effective_tenant,
        "snapshot_id": snapshot_id,
        "policy_hash": policy_hash,
        "snapshot": canonical_snapshot,
        "schema_version": canonical_snapshot.get("schema_version"),
        "compiler_version": canonical_snapshot.get("compiler_version"),
        "created_at": created_at,
        "deduped": False,
    }


def get_resolved_policy_snapshot(
    *,
    tenant_id: Optional[str],
    snapshot_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT snapshot_id, policy_hash, snapshot_json, schema_version, compiler_version, created_at
        FROM policy_resolved_snapshots
        WHERE tenant_id = ? AND snapshot_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(snapshot_id)),
    )
    if not row:
        return None
    payload = row.get("snapshot_json")
    try:
        snapshot = json.loads(payload) if isinstance(payload, str) else (payload or {})
    except Exception:
        snapshot = {}
    return {
        "tenant_id": effective_tenant,
        "snapshot_id": row.get("snapshot_id"),
        "policy_hash": row.get("policy_hash"),
        "snapshot": snapshot,
        "schema_version": row.get("schema_version"),
        "compiler_version": row.get("compiler_version"),
        "created_at": row.get("created_at"),
    }


def get_resolved_policy_snapshot_by_hash(
    *,
    tenant_id: Optional[str],
    policy_hash: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT snapshot_id
        FROM policy_resolved_snapshots
        WHERE tenant_id = ? AND policy_hash = ?
        LIMIT 1
        """,
        (effective_tenant, str(policy_hash)),
    )
    if not row:
        return None
    return get_resolved_policy_snapshot(
        tenant_id=effective_tenant,
        snapshot_id=str(row.get("snapshot_id") or ""),
    )


def record_policy_decision_binding(
    *,
    tenant_id: Optional[str],
    decision_id: str,
    snapshot_id: str,
    policy_hash: str,
    decision: str,
    reason_codes: Optional[Sequence[str]],
    signal_bundle_hash: Optional[str],
    issue_key: Optional[str] = None,
    transition_id: Optional[str] = None,
    actor_id: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    created_at = _utc_now()
    normalised_codes = _normalise_reason_codes(reason_codes)
    storage.execute(
        """
        INSERT INTO policy_decision_records (
            tenant_id, decision_id, issue_key, transition_id, actor_id, snapshot_id, policy_hash,
            decision, reason_codes_json, signal_bundle_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, decision_id) DO NOTHING
        """,
        (
            effective_tenant,
            str(decision_id),
            str(issue_key or "") or None,
            str(transition_id or "") or None,
            str(actor_id or "") or None,
            str(snapshot_id),
            str(policy_hash),
            str(decision),
            canonical_json(normalised_codes),
            str(signal_bundle_hash or "") or None,
            created_at,
        ),
    )
    row = storage.fetchone(
        """
        SELECT tenant_id, decision_id, issue_key, transition_id, actor_id, snapshot_id, policy_hash,
               decision, reason_codes_json, signal_bundle_hash, created_at
        FROM policy_decision_records
        WHERE tenant_id = ? AND decision_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(decision_id)),
    )
    if not row:
        return {
            "tenant_id": effective_tenant,
            "decision_id": str(decision_id),
            "snapshot_id": str(snapshot_id),
            "policy_hash": str(policy_hash),
            "decision": str(decision),
            "reason_codes": normalised_codes,
            "signal_bundle_hash": signal_bundle_hash,
            "created_at": created_at,
        }
    raw_codes = row.get("reason_codes_json")
    try:
        parsed_codes = json.loads(raw_codes) if isinstance(raw_codes, str) else (raw_codes or [])
    except Exception:
        parsed_codes = []
    return {
        "tenant_id": row.get("tenant_id"),
        "decision_id": row.get("decision_id"),
        "issue_key": row.get("issue_key"),
        "transition_id": row.get("transition_id"),
        "actor_id": row.get("actor_id"),
        "snapshot_id": row.get("snapshot_id"),
        "policy_hash": row.get("policy_hash"),
        "decision": row.get("decision"),
        "reason_codes": parsed_codes,
        "signal_bundle_hash": row.get("signal_bundle_hash"),
        "created_at": row.get("created_at"),
    }


def get_policy_decision_binding(
    *,
    tenant_id: Optional[str],
    decision_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT tenant_id, decision_id, issue_key, transition_id, actor_id, snapshot_id, policy_hash,
               decision, reason_codes_json, signal_bundle_hash, created_at
        FROM policy_decision_records
        WHERE tenant_id = ? AND decision_id = ?
        LIMIT 1
        """,
        (effective_tenant, str(decision_id)),
    )
    if not row:
        return None
    raw_codes = row.get("reason_codes_json")
    try:
        parsed_codes = json.loads(raw_codes) if isinstance(raw_codes, str) else (raw_codes or [])
    except Exception:
        parsed_codes = []
    return {
        "tenant_id": row.get("tenant_id"),
        "decision_id": row.get("decision_id"),
        "issue_key": row.get("issue_key"),
        "transition_id": row.get("transition_id"),
        "actor_id": row.get("actor_id"),
        "snapshot_id": row.get("snapshot_id"),
        "policy_hash": row.get("policy_hash"),
        "decision": row.get("decision"),
        "reason_codes": parsed_codes,
        "signal_bundle_hash": row.get("signal_bundle_hash"),
        "created_at": row.get("created_at"),
    }


def get_decision_with_snapshot(
    *,
    tenant_id: Optional[str],
    decision_id: str,
) -> Optional[Dict[str, Any]]:
    decision_binding = get_policy_decision_binding(tenant_id=tenant_id, decision_id=decision_id)
    if not decision_binding:
        return None
    snapshot = get_resolved_policy_snapshot(
        tenant_id=tenant_id,
        snapshot_id=str(decision_binding.get("snapshot_id") or ""),
    )
    if not snapshot:
        return {
            **decision_binding,
            "snapshot": None,
        }
    return {
        **decision_binding,
        "snapshot": snapshot,
    }


def verify_decision_snapshot_binding(
    *,
    tenant_id: Optional[str],
    decision_id: str,
) -> Dict[str, Any]:
    payload = get_decision_with_snapshot(tenant_id=tenant_id, decision_id=decision_id)
    if not payload:
        return {
            "exists": False,
            "verified": False,
            "reason": "decision binding not found",
        }
    snapshot_wrapper = payload.get("snapshot") or {}
    snapshot = snapshot_wrapper.get("snapshot") if isinstance(snapshot_wrapper, dict) else {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    expected = str(payload.get("policy_hash") or "")
    computed = compute_snapshot_policy_hash(snapshot)
    return {
        "exists": True,
        "verified": expected == computed,
        "decision_id": payload.get("decision_id"),
        "snapshot_id": payload.get("snapshot_id"),
        "expected_policy_hash": expected,
        "computed_policy_hash": computed,
        "tenant_id": payload.get("tenant_id"),
    }
