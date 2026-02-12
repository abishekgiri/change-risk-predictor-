from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


class ArtifactStore:
    """
    Narrow storage boundary for tenant-scoped governance artifacts.
    """

    def __init__(self):
        self.backend = get_storage_backend()

    def store_policy_snapshot(
        self,
        *,
        tenant_id: str,
        policy_bundle_hash: str,
        policy_snapshot: List[Dict[str, Any]],
        is_active: bool = True,
    ) -> None:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        self.backend.execute(
            """
            INSERT INTO policy_bundles (tenant_id, policy_bundle_hash, bundle_json, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, policy_bundle_hash) DO UPDATE SET
                bundle_json = excluded.bundle_json,
                is_active = excluded.is_active
            """,
            (
                effective_tenant,
                policy_bundle_hash,
                json.dumps(policy_snapshot or [], sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                1 if is_active else 0,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def get_policy_snapshot(self, *, tenant_id: str, policy_bundle_hash: str) -> Optional[Dict[str, Any]]:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        row = self.backend.fetchone(
            """
            SELECT tenant_id, policy_bundle_hash, bundle_json, is_active, created_at
            FROM policy_bundles
            WHERE tenant_id = ? AND policy_bundle_hash = ?
            LIMIT 1
            """,
            (effective_tenant, policy_bundle_hash),
        )
        if not row:
            return None
        snapshot = json.loads(row["bundle_json"]) if isinstance(row.get("bundle_json"), str) else row.get("bundle_json")
        return {
            "tenant_id": row["tenant_id"],
            "policy_bundle_hash": row["policy_bundle_hash"],
            "policy_snapshot": snapshot or [],
            "is_active": bool(row.get("is_active")),
            "created_at": row.get("created_at"),
        }

    def get_latest_active_policy_bundle(self, *, tenant_id: str) -> Optional[Dict[str, Any]]:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        row = self.backend.fetchone(
            """
            SELECT tenant_id, policy_bundle_hash, bundle_json, is_active, created_at
            FROM policy_bundles
            WHERE tenant_id = ? AND is_active = 1
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (effective_tenant,),
        )
        if not row:
            return None
        snapshot = json.loads(row["bundle_json"]) if isinstance(row.get("bundle_json"), str) else row.get("bundle_json")
        return {
            "tenant_id": row["tenant_id"],
            "policy_bundle_hash": row["policy_bundle_hash"],
            "policy_snapshot": snapshot or [],
            "is_active": bool(row.get("is_active")),
            "created_at": row.get("created_at"),
        }

    def store_decision(
        self,
        *,
        tenant_id: str,
        decision_id: str,
        context_id: str,
        repo: str,
        pr_number: Optional[int],
        release_status: str,
        policy_bundle_hash: str,
        engine_version: str,
        decision_hash: str,
        full_decision_json: str,
        evaluation_key: Optional[str],
        created_at: Optional[str] = None,
    ) -> None:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        self.backend.execute(
            """
            INSERT INTO audit_decisions (
                decision_id, tenant_id, context_id, repo, pr_number, release_status,
                policy_bundle_hash, engine_version, decision_hash, full_decision_json, created_at, evaluation_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision_id,
                effective_tenant,
                context_id,
                repo,
                pr_number,
                release_status,
                policy_bundle_hash,
                engine_version,
                decision_hash,
                full_decision_json,
                created_at or datetime.now(timezone.utc).isoformat(),
                evaluation_key,
            ),
        )

    def get_decision(self, *, tenant_id: str, decision_id: str) -> Optional[Dict[str, Any]]:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        return self.backend.fetchone(
            "SELECT * FROM audit_decisions WHERE tenant_id = ? AND decision_id = ?",
            (effective_tenant, decision_id),
        )

    def list_decisions(
        self,
        *,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        return self.backend.fetchall(
            """
            SELECT *
            FROM audit_decisions
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (effective_tenant, limit, offset),
        )

    def store_checkpoint(
        self,
        *,
        tenant_id: str,
        checkpoint_id: str,
        payload: Dict[str, Any],
        signature_algorithm: str,
        signature_value: str,
        path: Optional[str] = None,
    ) -> None:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        self.backend.execute(
            """
            INSERT INTO audit_checkpoints (
                checkpoint_id, tenant_id, repo, pr_number, cadence, period_id, period_end, root_hash, event_count,
                signature_algorithm, signature_value, path, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, checkpoint_id) DO NOTHING
            """,
            (
                checkpoint_id,
                effective_tenant,
                payload.get("repo"),
                payload.get("pr_number"),
                payload.get("cadence"),
                payload.get("period_id"),
                payload.get("period_end"),
                payload.get("root_hash"),
                int(payload.get("event_count", 0)),
                signature_algorithm,
                signature_value,
                path,
                payload.get("generated_at") or datetime.now(timezone.utc).isoformat(),
            ),
        )

    def get_checkpoint(self, *, tenant_id: str, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        return self.backend.fetchone(
            "SELECT * FROM audit_checkpoints WHERE tenant_id = ? AND checkpoint_id = ?",
            (effective_tenant, checkpoint_id),
        )

    def store_proof_pack(
        self,
        *,
        tenant_id: str,
        proof_pack_id: Optional[str],
        decision_id: str,
        output_format: str,
        bundle_version: str,
        repo: Optional[str] = None,
        pr_number: Optional[int] = None,
    ) -> str:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        pack_id = proof_pack_id or uuid.uuid4().hex
        self.backend.execute(
            """
            INSERT INTO audit_proof_packs (
                proof_pack_id, tenant_id, decision_id, repo, pr_number, output_format, bundle_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pack_id,
                effective_tenant,
                decision_id,
                repo,
                pr_number,
                output_format,
                bundle_version,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return pack_id

    def get_proof_pack(self, *, tenant_id: str, proof_pack_id: str) -> Optional[Dict[str, Any]]:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        return self.backend.fetchone(
            "SELECT * FROM audit_proof_packs WHERE tenant_id = ? AND proof_pack_id = ?",
            (effective_tenant, proof_pack_id),
        )

    def get_proof_pack_by_decision(self, *, tenant_id: str, decision_id: str) -> List[Dict[str, Any]]:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        return self.backend.fetchall(
            """
            SELECT *
            FROM audit_proof_packs
            WHERE tenant_id = ? AND decision_id = ?
            ORDER BY created_at DESC
            """,
            (effective_tenant, decision_id),
        )

    def store_override(
        self,
        *,
        tenant_id: str,
        override_id: str,
        payload: Dict[str, Any],
    ) -> None:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        self.backend.execute(
            """
            INSERT INTO audit_overrides (
                override_id, tenant_id, decision_id, repo, pr_number, issue_key, actor, reason,
                target_type, target_id, idempotency_key, previous_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                override_id,
                effective_tenant,
                payload.get("decision_id"),
                payload.get("repo"),
                payload.get("pr_number"),
                payload.get("issue_key"),
                payload.get("actor"),
                payload.get("reason"),
                payload.get("target_type"),
                payload.get("target_id"),
                payload.get("idempotency_key"),
                payload.get("previous_hash"),
                payload.get("event_hash"),
                payload.get("created_at") or datetime.now(timezone.utc).isoformat(),
            ),
        )

    def get_active_override(self, *, tenant_id: str, target_type: str, target_id: str) -> Optional[Dict[str, Any]]:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        return self.backend.fetchone(
            """
            SELECT *
            FROM audit_overrides
            WHERE tenant_id = ? AND target_type = ? AND target_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (effective_tenant, target_type, target_id),
        )

    def append_metric_event(
        self,
        *,
        tenant_id: str,
        metric_name: str,
        metric_value: int = 1,
        event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        init_db()
        effective_tenant = resolve_tenant_id(tenant_id)
        generated_id = event_id or uuid.uuid4().hex
        self.backend.execute(
            """
            INSERT INTO metrics_events (tenant_id, event_id, metric_name, metric_value, created_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                generated_id,
                metric_name,
                int(metric_value),
                datetime.now(timezone.utc).isoformat(),
                json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=False),
            ),
        )
        return generated_id
