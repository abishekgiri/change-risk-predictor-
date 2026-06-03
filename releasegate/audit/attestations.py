from __future__ import annotations

import json
import string
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.audit.transparency import record_transparency_for_attestation
from releasegate.config import is_anchoring_enabled
from releasegate.storage import get_storage_backend, is_storage_unavailable_error
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _ensure_audit_attestations_table() -> None:
    """
    Backward-compatible bootstrap for branches/environments where migration
    20260213_011 has not been applied yet.

    Per migration 20260430_044, the (tenant_id, decision_id) UNIQUE index
    is intentionally NOT created here — `attestation_id` (= signed_payload_hash)
    is per-run unique by definition, and the legacy index forced one row
    per (tenant, decision_id) which collapsed re-runs of the same
    deterministic decision_id (#128) onto a single audit row.  The
    PRIMARY KEY (tenant_id, attestation_id) provides per-run uniqueness
    on its own.
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
    # Defensive drop in case an older version of this bootstrap created the
    # legacy index before migration 044 ran.  Idempotent.
    storage.execute(
        "DROP INDEX IF EXISTS uq_audit_attestations_tenant_decision"
    )
    _ensure_attestation_append_only(storage)


def _ensure_attestation_append_only(storage) -> None:
    if storage.name == "postgres":
        storage.execute(
            """
            CREATE OR REPLACE FUNCTION releasegate_prevent_attestation_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'Attestation log is append-only: % not allowed', TG_OP;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        storage.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_trigger
                    WHERE tgname = 'prevent_attestations_update'
                ) THEN
                    CREATE TRIGGER prevent_attestations_update
                    BEFORE UPDATE ON audit_attestations
                    FOR EACH ROW
                    EXECUTE FUNCTION releasegate_prevent_attestation_mutation();
                END IF;
            END $$;
            """
        )
        storage.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_trigger
                    WHERE tgname = 'prevent_attestations_delete'
                ) THEN
                    CREATE TRIGGER prevent_attestations_delete
                    BEFORE DELETE ON audit_attestations
                    FOR EACH ROW
                    EXECUTE FUNCTION releasegate_prevent_attestation_mutation();
                END IF;
            END $$;
            """
        )
        return

    storage.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_attestations_update
        BEFORE UPDATE ON audit_attestations
        BEGIN
            SELECT RAISE(FAIL, 'Attestation log is append-only: UPDATE not allowed');
        END;
        """
    )
    storage.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_attestations_delete
        BEFORE DELETE ON audit_attestations
        BEGIN
            SELECT RAISE(FAIL, 'Attestation log is append-only: DELETE not allowed');
        END;
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
    """Record a signed release attestation.

    Per-run uniqueness contract (post-#128 / migration 044):
      `attestation_id = signed_payload_hash`, which is per-run unique by
      definition (each CI invocation produces its own DSSE signature over a
      payload that includes run-of-record fields like workflow_run.run_id).
      `decision_id` is deterministic across re-runs of the same PR (#128),
      so the same `decision_id` may legitimately appear in many rows of
      `audit_attestations` — one per signing event.

    Idempotency contract (unchanged):
      Calling this function twice with the *same* signed attestation
      (same `signed_payload_hash`) is a no-op for the second call: the
      INSERT collides on PRIMARY KEY (tenant_id, attestation_id) and is
      swallowed by `ON CONFLICT DO NOTHING`.  The transparency log entry
      is also idempotent (its own UNIQUE index on (tenant_id,
      attestation_id) at `audit_transparency_log`).
    """
    # Derive the attestation_id first.  This is a pure function of the
    # signed payload (attestation_id == normalized signed_payload_hash) and
    # needs no database.  The customer-side signing path — a CI runner with
    # no DB configured — must get a valid id even when persistence is
    # impossible, so the DSSE envelope and the report can reference it.
    signature = attestation.get("signature") or {}
    signed_payload_hash = str(signature.get("signed_payload_hash") or "")
    normalized_hash = _normalize_signed_payload_hash(signed_payload_hash)
    payload_hash = f"sha256:{normalized_hash}"
    attestation_id = _attestation_id(signed_payload_hash=signed_payload_hash)

    # Persistence is optional.  When no DB backend is reachable (the
    # stateless customer path) we skip it silently and return the derived
    # id.  Genuine storage errors are NOT swallowed — they re-raise.  The
    # dashboard ingest path always has a backend, so it always persists.
    try:
        init_db()
        _ensure_audit_attestations_table()
        storage = get_storage_backend()
        effective_tenant = resolve_tenant_id(tenant_id)
        algorithm = str(signature.get("algorithm") or "ed25519")
        key_id = str((attestation.get("issuer") or {}).get("key_id") or "")
        schema_version = str(attestation.get("schema_version") or "1.0.0")
        created_at = datetime.now(timezone.utc).isoformat()

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
        if is_anchoring_enabled():
            record_transparency_for_attestation(
                tenant_id=effective_tenant,
                attestation_id=attestation_id,
                fallback_repo=repo,
                fallback_pr_number=pr_number,
                payload_hash=payload_hash,
                attestation=attestation,
            )
    except Exception as exc:
        if is_storage_unavailable_error(exc):
            return attestation_id
        raise
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


def list_release_attestations(
    *,
    tenant_id: Optional[str] = None,
    repo: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    init_db()
    _ensure_audit_attestations_table()
    storage = get_storage_backend()

    try:
        effective_limit = max(1, min(int(limit), 500))
    except Exception as exc:
        raise ValueError("limit must be an integer") from exc

    since_dt = None
    if since:
        text = str(since).strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            since_dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError("since must be ISO8601 date-time") from exc
        if since_dt.tzinfo is None:
            since_dt = since_dt.replace(tzinfo=timezone.utc)
        else:
            since_dt = since_dt.astimezone(timezone.utc)

    filters = []
    params = []
    if tenant_id is not None:
        filters.append("tenant_id = ?")
        params.append(resolve_tenant_id(tenant_id))
    if repo is not None:
        filters.append("repo = ?")
        params.append(str(repo))

    where_clause = ""
    if filters:
        where_clause = "WHERE " + " AND ".join(filters)

    rows = storage.fetchall(
        f"""
        SELECT tenant_id, attestation_id, decision_id, repo, pr_number,
               schema_version, key_id, algorithm, signed_payload_hash,
               attestation_json, created_at
        FROM audit_attestations
        {where_clause}
        ORDER BY created_at DESC
        LIMIT ?
        """,
        tuple(params + [effective_limit]),
    )

    items = []
    for row in rows:
        created_at = str(row.get("created_at") or "")
        created_dt = None
        if created_at:
            raw = created_at[:-1] + "+00:00" if created_at.endswith("Z") else created_at
            try:
                created_dt = datetime.fromisoformat(raw)
            except ValueError:
                created_dt = None
        if created_dt is not None:
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            else:
                created_dt = created_dt.astimezone(timezone.utc)
        if since_dt is not None and created_dt is not None and created_dt < since_dt:
            continue

        payload_raw = row.get("attestation_json")
        payload = json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
        items.append(
            {
                "tenant_id": row.get("tenant_id"),
                "attestation_id": row.get("attestation_id"),
                "decision_id": row.get("decision_id"),
                "repo": row.get("repo"),
                "pr_number": row.get("pr_number"),
                "schema_version": row.get("schema_version"),
                "key_id": row.get("key_id"),
                "algorithm": row.get("algorithm"),
                "signed_payload_hash": row.get("signed_payload_hash"),
                "created_at": row.get("created_at"),
                "attestation": payload,
            }
        )

    return {
        "ok": True,
        "limit": effective_limit,
        "count": len(items),
        "items": items,
    }
