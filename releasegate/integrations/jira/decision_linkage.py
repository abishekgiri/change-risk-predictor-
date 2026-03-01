from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Set, Tuple

from releasegate.audit.reader import AuditReader
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


DEFAULT_DECISION_LINK_TTL_SECONDS = 10 * 60
DEFAULT_PROTECTED_STATUSES = "done,released,prod deploy"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_status(value: str) -> str:
    return str(value or "").strip().lower()


def protected_statuses_from_env() -> Set[str]:
    raw = str(os.getenv("RELEASEGATE_PROTECTED_STATUSES", DEFAULT_PROTECTED_STATUSES) or "")
    return {_normalize_status(part) for part in raw.split(",") if _normalize_status(part)}


def is_protected_status(target_status: str) -> bool:
    return _normalize_status(target_status) in protected_statuses_from_env()


def build_context_payload(
    *,
    tenant_id: str,
    issue_key: str,
    transition_id: str,
    actor_account_id: str,
    source_status: str,
    target_status: str,
    environment: Optional[str],
    project_key: Optional[str],
) -> Dict[str, Any]:
    return {
        "tenant_id": str(tenant_id or "").strip(),
        "jira_issue_id": str(issue_key or "").strip(),
        "transition_id": str(transition_id or "").strip(),
        "actor": str(actor_account_id or "").strip(),
        "source_status": str(source_status or "").strip(),
        "target_status": str(target_status or "").strip(),
        "environment": str(environment or "").strip(),
        "project_key": str(project_key or "").strip(),
    }


def compute_context_hash(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_expires_at() -> str:
    ttl_raw = str(os.getenv("RELEASEGATE_DECISION_LINK_TTL_SECONDS", str(DEFAULT_DECISION_LINK_TTL_SECONDS)) or "")
    try:
        ttl_seconds = max(1, int(ttl_raw))
    except Exception:
        ttl_seconds = DEFAULT_DECISION_LINK_TTL_SECONDS
    return (_utc_now() + timedelta(seconds=ttl_seconds)).isoformat()


def _parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extract_policy_ref(decision_row: Dict[str, Any]) -> tuple[str, str, str]:
    policy_id = "unknown"
    policy_version = "unknown"
    policy_hash = str(
        decision_row.get("policy_hash")
        or decision_row.get("policy_bundle_hash")
        or ""
    ).strip()

    raw_full = decision_row.get("full_decision_json")
    payload: Dict[str, Any] = {}
    if isinstance(raw_full, dict):
        payload = raw_full
    elif isinstance(raw_full, str) and raw_full.strip():
        try:
            parsed = json.loads(raw_full)
            if isinstance(parsed, dict):
                payload = parsed
        except Exception:
            payload = {}

    bindings = payload.get("policy_bindings")
    if isinstance(bindings, list):
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            binding_policy_id = str(binding.get("policy_id") or "").strip()
            if not binding_policy_id:
                continue
            policy_id = binding_policy_id
            policy_version = str(binding.get("policy_version") or "unknown").strip() or "unknown"
            binding_hash = str(binding.get("policy_hash") or "").strip()
            if binding_hash:
                policy_hash = binding_hash
            break

    if not policy_hash:
        policy_hash = "unknown"
    return policy_id, policy_version, policy_hash


def register_transition_decision_link(
    *,
    tenant_id: str,
    decision_id: str,
    issue_key: str,
    transition_id: str,
    actor_account_id: str,
    source_status: str,
    target_status: str,
    environment: Optional[str],
    project_key: Optional[str],
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = AuditReader.get_decision(decision_id=decision_id, tenant_id=effective_tenant)
    if row:
        policy_id, policy_version, policy_hash = _extract_policy_ref(row)
    else:
        policy_id, policy_version, policy_hash = ("unknown", "unknown", "unknown")
    context_payload = build_context_payload(
        tenant_id=effective_tenant,
        issue_key=issue_key,
        transition_id=transition_id,
        actor_account_id=actor_account_id,
        source_status=source_status,
        target_status=target_status,
        environment=environment,
        project_key=project_key,
    )
    context_hash = compute_context_hash(context_payload)
    expires_at = compute_expires_at()

    storage.execute(
        """
        INSERT INTO decision_transition_links (
            tenant_id,
            decision_id,
            jira_issue_id,
            transition_id,
            actor,
            source_status,
            target_status,
            policy_id,
            policy_version,
            policy_hash,
            context_hash,
            expires_at,
            consumed,
            consumed_at,
            consumed_by_request_id,
            created_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?
        )
        ON CONFLICT (tenant_id, decision_id) DO NOTHING
        """,
        (
            effective_tenant,
            decision_id,
            str(issue_key or "").strip(),
            str(transition_id or "").strip(),
            str(actor_account_id or "").strip(),
            str(source_status or "").strip(),
            str(target_status or "").strip(),
            policy_id,
            policy_version,
            policy_hash,
            context_hash,
            expires_at,
            _utc_now().isoformat(),
        ),
    )

    stored = get_decision_linkage(tenant_id=effective_tenant, decision_id=decision_id)
    if not stored:
        raise ValueError("LINK_NOT_FOUND")
    if str(stored.get("context_hash") or "") != context_hash:
        raise ValueError("LINK_CONTEXT_CONFLICT")
    return stored


def get_decision_linkage(*, tenant_id: str, decision_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    return storage.fetchone(
        """
        SELECT *
        FROM decision_transition_links
        WHERE tenant_id = ? AND decision_id = ?
        """,
        (effective_tenant, decision_id),
    )


def validate_and_consume_decision_link(
    *,
    tenant_id: str,
    decision_id: str,
    expected_context_hash: str,
    request_id: Optional[str] = None,
) -> Tuple[bool, str]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_request_id = str(request_id or "").strip() or None

    row = storage.fetchone(
        """
        SELECT *
        FROM decision_transition_links
        WHERE tenant_id = ? AND decision_id = ?
        """,
        (effective_tenant, decision_id),
    )
    if not row:
        return False, "LINK_NOT_FOUND"

    expires_at = _parse_datetime(row.get("expires_at"))
    if not expires_at or _utc_now() > expires_at:
        return False, "LINK_EXPIRED"

    if str(row.get("context_hash") or "") != str(expected_context_hash or ""):
        return False, "LINK_CONTEXT_MISMATCH"

    if int(row.get("consumed") or 0) == 1:
        existing_request_id = str(row.get("consumed_by_request_id") or "").strip() or None
        if normalized_request_id and existing_request_id and existing_request_id == normalized_request_id:
            return True, "OK_IDEMPOTENT"
        return False, "LINK_ALREADY_CONSUMED"

    affected = storage.execute(
        """
        UPDATE decision_transition_links
        SET consumed = 1,
            consumed_at = ?,
            consumed_by_request_id = ?
        WHERE tenant_id = ?
          AND decision_id = ?
          AND consumed = 0
        """,
        (
            _utc_now().isoformat(),
            normalized_request_id,
            effective_tenant,
            decision_id,
        ),
    )
    if affected == 1:
        return True, "OK"

    # Concurrent race: re-read and allow idempotent replay for same request id.
    row = storage.fetchone(
        """
        SELECT consumed_by_request_id
        FROM decision_transition_links
        WHERE tenant_id = ? AND decision_id = ?
        """,
        (effective_tenant, decision_id),
    )
    existing_request_id = str((row or {}).get("consumed_by_request_id") or "").strip() or None
    if normalized_request_id and existing_request_id and existing_request_id == normalized_request_id:
        return True, "OK_IDEMPOTENT"
    return False, "LINK_ALREADY_CONSUMED"
