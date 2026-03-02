from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.governance.signal_freshness import compute_risk_signal_hash
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_signal_hash(payload: Dict[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(payload).encode('utf-8')).hexdigest()}"


def resolve_signal_attestation_policy(
    *,
    policy_overrides: Optional[Dict[str, Any]],
    strict_enabled: bool,
) -> Dict[str, Any]:
    overrides = policy_overrides if isinstance(policy_overrides, dict) else {}
    max_age_raw = (
        overrides.get("max_age_seconds")
        or os.getenv("RELEASEGATE_MAX_SIGNAL_AGE_SECONDS")
        or os.getenv("RELEASEGATE_SIGNAL_MAX_AGE_SECONDS")
        or "86400"
    )
    try:
        max_age_seconds = max(1, int(max_age_raw))
    except Exception:
        max_age_seconds = 86400

    require_record_raw = overrides.get("require_attestation_record")
    if require_record_raw is None:
        require_record_raw = os.getenv("RELEASEGATE_REQUIRE_SIGNAL_ATTESTATION", "false")
    require_record = str(require_record_raw).strip().lower() in {"1", "true", "yes", "on"}

    def _as_bool(value: Any, *, default: bool) -> bool:
        if value is None:
            return default
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    require_source_default = require_record
    require_hash_default = require_record
    require_expiration_default = require_record
    require_computed_at_default = True

    return {
        "max_age_seconds": max_age_seconds,
        "require_signal_source": _as_bool(overrides.get("require_signal_source"), default=require_source_default),
        "require_computed_at": _as_bool(overrides.get("require_computed_at"), default=require_computed_at_default),
        "require_signal_hash": _as_bool(overrides.get("require_signal_hash"), default=require_hash_default),
        "require_expiration": _as_bool(overrides.get("require_expiration"), default=require_expiration_default),
        "require_attestation_record": require_record,
        "fail_closed": _as_bool(overrides.get("fail_closed"), default=True),
        "strict_enabled": bool(strict_enabled),
    }


def attest_signal(
    *,
    tenant_id: str,
    signal_type: str,
    signal_source: str,
    subject_type: str,
    subject_id: str,
    computed_at: str,
    expires_at: str,
    payload: Dict[str, Any],
    signal_hash: Optional[str] = None,
    sig_alg: Optional[str] = None,
    signature: Optional[str] = None,
    key_id: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_signal_type = str(signal_type or "").strip().lower()
    normalized_source = str(signal_source or "").strip()
    normalized_subject_type = str(subject_type or "").strip().lower()
    normalized_subject_id = str(subject_id or "").strip()
    computed_dt = _parse_datetime(computed_at)
    expires_dt = _parse_datetime(expires_at)
    if not normalized_signal_type:
        raise ValueError("SIGNAL_TYPE_REQUIRED")
    if not normalized_source:
        raise ValueError("SIGNAL_SOURCE_REQUIRED")
    if not normalized_subject_type or not normalized_subject_id:
        raise ValueError("SIGNAL_SUBJECT_REQUIRED")
    if computed_dt is None:
        raise ValueError("SIGNAL_COMPUTED_AT_INVALID")
    if expires_dt is None:
        raise ValueError("SIGNAL_EXPIRES_AT_INVALID")
    if expires_dt <= computed_dt:
        raise ValueError("SIGNAL_EXPIRATION_INVALID")
    if not isinstance(payload, dict):
        raise ValueError("SIGNAL_PAYLOAD_INVALID")

    canonical_payload = {
        "signal_type": normalized_signal_type,
        "signal_source": normalized_source,
        "subject_type": normalized_subject_type,
        "subject_id": normalized_subject_id,
        "computed_at": computed_dt.isoformat(),
        "expires_at": expires_dt.isoformat(),
        "payload": payload,
    }
    expected_hash = compute_signal_hash(canonical_payload)
    provided_hash = str(signal_hash or "").strip()
    if provided_hash and provided_hash != expected_hash:
        raise ValueError("INVALID_SIGNAL")
    resolved_hash = provided_hash or expected_hash
    signal_id = str(uuid.uuid4())
    created_at = _utc_now().isoformat()

    storage.execute(
        """
        INSERT INTO signal_attestations (
            tenant_id,
            signal_id,
            signal_type,
            signal_source,
            subject_type,
            subject_id,
            computed_at,
            expires_at,
            payload_json,
            signal_hash,
            sig_alg,
            signature,
            key_id,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            signal_id,
            normalized_signal_type,
            normalized_source,
            normalized_subject_type,
            normalized_subject_id,
            computed_dt.isoformat(),
            expires_dt.isoformat(),
            _canonical_json(payload),
            resolved_hash,
            str(sig_alg or "").strip() or None,
            str(signature or "").strip() or None,
            str(key_id or "").strip() or None,
            created_at,
        ),
    )
    row = get_latest_signal_attestation(
        tenant_id=effective_tenant,
        signal_type=normalized_signal_type,
        subject_type=normalized_subject_type,
        subject_id=normalized_subject_id,
    )
    if not row:
        raise RuntimeError("SIGNAL_ATTESTATION_WRITE_FAILED")
    return row


def get_latest_signal_attestation(
    *,
    tenant_id: str,
    signal_type: str,
    subject_type: str,
    subject_id: str,
) -> Optional[Dict[str, Any]]:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    row = storage.fetchone(
        """
        SELECT *
        FROM signal_attestations
        WHERE tenant_id = ?
          AND signal_type = ?
          AND subject_type = ?
          AND subject_id = ?
        ORDER BY computed_at DESC, created_at DESC
        LIMIT 1
        """,
        (
            effective_tenant,
            str(signal_type or "").strip().lower(),
            str(subject_type or "").strip().lower(),
            str(subject_id or "").strip(),
        ),
    )
    if not row:
        return None
    payload_raw = row.get("payload_json")
    payload_json: Dict[str, Any] = {}
    if isinstance(payload_raw, dict):
        payload_json = payload_raw
    elif isinstance(payload_raw, str) and payload_raw.strip():
        try:
            parsed = json.loads(payload_raw)
            if isinstance(parsed, dict):
                payload_json = parsed
        except Exception:
            payload_json = {}
    enriched = dict(row)
    enriched["payload_json"] = payload_json
    return enriched


def evaluate_signal_attestation(
    *,
    tenant_id: str,
    signal_type: str,
    subject_type: str,
    subject_id: str,
    inline_signal: Optional[Dict[str, Any]],
    policy: Dict[str, Any],
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    evaluated_at = now or _utc_now()
    if evaluated_at.tzinfo is None:
        evaluated_at = evaluated_at.replace(tzinfo=timezone.utc)
    evaluated_at = evaluated_at.astimezone(timezone.utc)

    strict_enabled = bool(policy.get("strict_enabled", False))
    fail_closed = bool(policy.get("fail_closed", True))
    require_record = bool(policy.get("require_attestation_record", False))
    require_source = bool(policy.get("require_signal_source", True))
    require_hash = bool(policy.get("require_signal_hash", True))
    require_expiration = bool(policy.get("require_expiration", True))
    require_computed_at = bool(policy.get("require_computed_at", True))
    max_age_seconds = int(policy.get("max_age_seconds", 86400) or 86400)

    report = {
        "valid": True,
        "stale": False,
        "should_block": False,
        "reason_code": None,
        "reason": "ok",
        "source": "inline",
        "max_age_seconds": max_age_seconds,
    }

    latest = get_latest_signal_attestation(
        tenant_id=tenant_id,
        signal_type=signal_type,
        subject_type=subject_type,
        subject_id=subject_id,
    )
    signal = inline_signal if isinstance(inline_signal, dict) else {}
    source = str(signal.get("signal_source") or signal.get("source") or "").strip()
    computed_at = _parse_datetime(signal.get("computed_at"))
    expires_at = _parse_datetime(signal.get("expires_at") or signal.get("expiration"))
    inline_hash = str(signal.get("signal_hash") or "").strip()
    inline_payload = signal.get("payload") if isinstance(signal.get("payload"), dict) else signal

    if latest:
        report["source"] = "attestation_record"
        canonical_payload = {
            "signal_type": str(latest.get("signal_type") or "").strip().lower(),
            "signal_source": str(latest.get("signal_source") or "").strip(),
            "subject_type": str(latest.get("subject_type") or "").strip().lower(),
            "subject_id": str(latest.get("subject_id") or "").strip(),
            "computed_at": str(latest.get("computed_at") or "").strip(),
            "expires_at": str(latest.get("expires_at") or "").strip(),
            "payload": latest.get("payload_json") if isinstance(latest.get("payload_json"), dict) else {},
        }
        expected_hash = compute_signal_hash(canonical_payload)
        stored_hash = str(latest.get("signal_hash") or "").strip()
        if not stored_hash or stored_hash != expected_hash:
            report.update(
                {
                    "valid": False,
                    "stale": True,
                    "reason_code": "INVALID_SIGNAL",
                    "reason": "stored signal attestation hash mismatch",
                }
            )
        else:
            source = str(latest.get("signal_source") or source).strip()
            computed_at = _parse_datetime(latest.get("computed_at"))
            expires_at = _parse_datetime(latest.get("expires_at"))
            inline_hash = stored_hash
            if signal_type == "risk_eval" and isinstance(latest.get("payload_json"), dict):
                inline_payload = latest.get("payload_json")
    elif require_record:
        report.update(
            {
                "valid": False,
                "stale": True,
                "reason_code": "MISSING_SIGNAL",
                "reason": "required signal attestation record is missing",
            }
        )

    if report["valid"] and require_source and not source:
        report.update(
            {
                "valid": False,
                "stale": True,
                "reason_code": "MISSING_SIGNAL",
                "reason": "signal_source is required",
            }
        )

    if report["valid"] and require_computed_at and computed_at is None:
        report.update(
            {
                "valid": False,
                "stale": True,
                "reason_code": "MISSING_SIGNAL",
                "reason": "computed_at is required",
            }
        )

    if report["valid"] and require_expiration and expires_at is None:
        report.update(
            {
                "valid": False,
                "stale": True,
                "reason_code": "MISSING_SIGNAL",
                "reason": "expiration is required",
            }
        )

    if report["valid"] and require_hash:
        if not inline_hash:
            report.update(
                {
                    "valid": False,
                    "stale": True,
                    "reason_code": "MISSING_SIGNAL",
                    "reason": "signal_hash is required",
                }
            )
        else:
            canonical_inline = {
                "signal_type": str(signal_type or "").strip().lower(),
                "signal_source": source,
                "subject_type": str(subject_type or "").strip().lower(),
                "subject_id": str(subject_id or "").strip(),
                "computed_at": computed_at.isoformat() if computed_at else "",
                "expires_at": expires_at.isoformat() if expires_at else "",
                "payload": inline_payload if isinstance(inline_payload, dict) else {},
            }
            expected_inline_hash = compute_signal_hash(canonical_inline)
            if inline_hash != expected_inline_hash:
                # Backward-compatible risk hash format.
                if signal_type == "risk_eval" and inline_hash == compute_risk_signal_hash(
                    inline_payload if isinstance(inline_payload, dict) else {}
                ):
                    pass
                else:
                    report.update(
                        {
                            "valid": False,
                            "stale": True,
                            "reason_code": "INVALID_SIGNAL",
                            "reason": "signal hash mismatch",
                        }
                    )

    if report["valid"] and computed_at is not None:
        age_seconds = int(max(0.0, (evaluated_at - computed_at).total_seconds()))
        report["age_seconds"] = age_seconds
        if max_age_seconds > 0 and age_seconds > max_age_seconds:
            report.update(
                {
                    "valid": False,
                    "stale": True,
                    "reason_code": "STALE_SIGNAL",
                    "reason": "signal is older than max_age_seconds",
                }
            )

    if report["valid"] and expires_at is not None and evaluated_at > expires_at:
        report.update(
            {
                "valid": False,
                "stale": True,
                "reason_code": "STALE_SIGNAL",
                "reason": "signal attestation expired",
            }
        )

    report["should_block"] = bool(report["stale"] and fail_closed and strict_enabled)
    return report
