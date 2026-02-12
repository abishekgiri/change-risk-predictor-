from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from releasegate.audit.policy_bundles import store_policy_bundle
from releasegate.decision.hashing import (
    compute_decision_hash,
    compute_input_hash,
    compute_policy_hash_from_bindings,
    compute_replay_hash,
)
from releasegate.decision.types import Decision
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


class AuditRecorder:
    """
    Writes decisions to immutable audit storage and stores tenant-bound policy snapshots.
    """

    ENGINE_VERSION = "0.2.0"

    @staticmethod
    def _canonical_decision(decision: Decision) -> str:
        raw_dict = decision.model_dump(mode="json")
        return json.dumps(raw_dict, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _attach_hashes(decision: Decision) -> None:
        release_status = decision.release_status.value if hasattr(decision.release_status, "value") else str(decision.release_status)
        if not decision.input_hash:
            decision.input_hash = compute_input_hash(decision.input_snapshot)
        if not decision.policy_hash:
            decision.policy_hash = compute_policy_hash_from_bindings([b.model_dump(mode="json") for b in decision.policy_bindings])
        if not decision.decision_hash:
            decision.decision_hash = compute_decision_hash(
                release_status=release_status,
                reason_code=decision.reason_code,
                policy_bundle_hash=decision.policy_bundle_hash,
                inputs_present=decision.inputs_present,
            )
        if not decision.replay_hash:
            decision.replay_hash = compute_replay_hash(
                input_hash=decision.input_hash,
                policy_hash=decision.policy_hash,
                decision_hash=decision.decision_hash,
            )

    @staticmethod
    def _persist_policy_snapshots(
        tenant_id: str,
        decision: Decision,
        created_at: str,
    ) -> None:
        if not decision.policy_bindings:
            return
        storage = get_storage_backend()
        for binding in decision.policy_bindings:
            policy_json = json.dumps(
                binding.policy or {},
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            storage.execute(
                """
                INSERT INTO policy_snapshots (
                    tenant_id, decision_id, policy_id, policy_version, policy_hash, policy_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, decision_id, policy_id) DO NOTHING
                """,
                (
                    tenant_id,
                    decision.decision_id,
                    binding.policy_id,
                    binding.policy_version,
                    binding.policy_hash,
                    policy_json,
                    created_at,
                ),
            )

    @staticmethod
    def record(decision: Decision) -> Decision:
        repo = decision.enforcement_targets.repository
        pr_number = decision.enforcement_targets.pr_number
        return AuditRecorder.record_with_context(decision, repo=repo, pr_number=pr_number, tenant_id=decision.tenant_id)

    @staticmethod
    def record_with_context(
        decision: Decision,
        repo: str,
        pr_number: Optional[int],
        tenant_id: Optional[str] = None,
    ) -> Decision:
        init_db()
        storage = get_storage_backend()
        effective_tenant = resolve_tenant_id(tenant_id or decision.tenant_id)
        decision.tenant_id = effective_tenant
        for binding in decision.policy_bindings:
            if not getattr(binding, "tenant_id", None):
                binding.tenant_id = effective_tenant

        AuditRecorder._attach_hashes(decision)
        canonical_json = AuditRecorder._canonical_decision(decision)
        created_at = decision.timestamp.astimezone(timezone.utc).isoformat()

        try:
            storage.execute(
                """
                INSERT INTO audit_decisions (
                    decision_id, tenant_id, context_id, repo, pr_number,
                    release_status, policy_bundle_hash, engine_version,
                    decision_hash, input_hash, policy_hash, replay_hash, full_decision_json, created_at, evaluation_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.decision_id,
                    effective_tenant,
                    decision.context_id,
                    repo,
                    pr_number,
                    decision.release_status,
                    decision.policy_bundle_hash,
                    AuditRecorder.ENGINE_VERSION,
                    decision.decision_hash,
                    decision.input_hash,
                    decision.policy_hash,
                    decision.replay_hash,
                    canonical_json,
                    created_at,
                    decision.evaluation_key,
                ),
            )
            AuditRecorder._persist_policy_snapshots(
                tenant_id=effective_tenant,
                decision=decision,
                created_at=created_at,
            )
            store_policy_bundle(
                tenant_id=effective_tenant,
                policy_bundle_hash=decision.policy_bundle_hash,
                policy_snapshot=[b.model_dump(mode="json") for b in decision.policy_bindings],
                is_active=True,
            )
            return decision
        except Exception as exc:
            # Idempotency collision on evaluation_key; return existing decision row.
            lowered = str(exc).lower()
            if decision.evaluation_key and ("evaluation_key" in lowered or "unique" in lowered):
                row = storage.fetchone(
                    """
                    SELECT full_decision_json
                    FROM audit_decisions
                    WHERE tenant_id = ? AND evaluation_key = ?
                    LIMIT 1
                    """,
                    (effective_tenant, decision.evaluation_key),
                )
                if row and row.get("full_decision_json"):
                    existing = row["full_decision_json"]
                    if isinstance(existing, str):
                        existing = json.loads(existing)
                    return Decision.model_validate(existing)
            raise
