from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, List, Optional, Sequence

from releasegate.audit.policy_bundles import store_policy_bundle
from releasegate.decision.hashing import (
    compute_decision_hash,
    compute_input_hash,
    compute_policy_hash_from_bindings,
    compute_replay_hash,
)
from releasegate.decision.types import Decision
from releasegate.policy.snapshots import (
    build_resolved_policy_snapshot,
    record_policy_decision_binding,
    store_resolved_policy_snapshot,
)
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
    def _persist_resolved_policy_snapshot_record(
        *,
        tenant_id: str,
        decision: Decision,
        repo: str,
        pr_number: Optional[int],
    ) -> None:
        policy_bindings = [
            binding.model_dump(mode="json", exclude_none=True)
            for binding in sorted(decision.policy_bindings, key=lambda b: b.policy_id)
        ]
        resolution_inputs = {
            "tenant_id": tenant_id,
            "repo": repo,
            "pr_number": pr_number,
            "context_id": decision.context_id,
            "actor_id": decision.actor_id,
            "evaluation_key": decision.evaluation_key,
        }
        if decision.input_snapshot:
            resolution_inputs["input_context"] = {
                "environment": decision.input_snapshot.get("environment"),
                "transition_id": decision.input_snapshot.get("transition_id"),
                "issue_key": decision.input_snapshot.get("issue_key"),
            }

        snapshot = build_resolved_policy_snapshot(
            policy_id="releasegate.resolved_bundle",
            policy_version=str(decision.policy_bundle_hash or "unknown"),
            resolution_inputs=resolution_inputs,
            resolved_policy={
                "policy_bundle_hash": decision.policy_bundle_hash,
                "policy_bindings": policy_bindings,
            },
        )
        persisted = store_resolved_policy_snapshot(
            tenant_id=tenant_id,
            snapshot=snapshot,
        )

        issue_key: Optional[str] = None
        try:
            jira_keys = getattr(getattr(decision.enforcement_targets, "external", None), "jira", []) or []
            if jira_keys:
                issue_key = str(jira_keys[0]).strip() or None
        except Exception:
            issue_key = None
        transition_id = None
        if isinstance(decision.input_snapshot, dict):
            raw_transition = decision.input_snapshot.get("transition_id")
            if raw_transition is not None:
                transition_id = str(raw_transition).strip() or None

        reason_codes = [decision.reason_code] if decision.reason_code else []
        record_policy_decision_binding(
            tenant_id=tenant_id,
            decision_id=decision.decision_id,
            issue_key=issue_key,
            transition_id=transition_id,
            actor_id=decision.actor_id,
            snapshot_id=str(persisted.get("snapshot_id") or ""),
            policy_hash=str(persisted.get("policy_hash") or ""),
            decision=decision.release_status.value if hasattr(decision.release_status, "value") else str(decision.release_status),
            reason_codes=reason_codes,
            signal_bundle_hash=decision.input_hash,
        )

    @staticmethod
    def _extract_decision_refs(decision: Decision) -> List[tuple[str, str]]:
        """
        Extract external references from a Decision for cross-system search.
        """
        refs: list[tuple[str, str]] = []

        # Jira issue keys (primary use case for multi-repo enforcement + change windows).
        try:
            jira_keys: Sequence[Any] = getattr(getattr(decision.enforcement_targets, "external", None), "jira", []) or []
        except Exception:
            jira_keys = []
        for raw in jira_keys:
            key = str(raw or "").strip()
            if key:
                refs.append(("jira", key))

        # Git ref/sha (optional but useful for later search and evidence).
        try:
            git_ref = str(getattr(decision.enforcement_targets, "ref", "") or "").strip()
        except Exception:
            git_ref = ""
        if git_ref:
            refs.append(("git_ref", git_ref))

        # Deterministic ordering + de-dupe.
        uniq = sorted(set(refs))
        return uniq

    @staticmethod
    def _persist_decision_refs(
        tenant_id: str,
        decision: Decision,
        repo: str,
        pr_number: Optional[int],
        created_at: str,
    ) -> None:
        refs = AuditRecorder._extract_decision_refs(decision)
        if not refs:
            return

        storage = get_storage_backend()
        for ref_type, ref_value in refs:
            storage.execute(
                """
                INSERT INTO audit_decision_refs (
                    tenant_id, decision_id, repo, pr_number, ref_type, ref_value, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, decision_id, ref_type, ref_value) DO NOTHING
                """,
                (
                    tenant_id,
                    decision.decision_id,
                    repo,
                    pr_number,
                    ref_type,
                    ref_value,
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
            AuditRecorder._persist_resolved_policy_snapshot_record(
                tenant_id=effective_tenant,
                decision=decision,
                repo=repo,
                pr_number=pr_number,
            )
            try:
                AuditRecorder._persist_decision_refs(
                    tenant_id=effective_tenant,
                    decision=decision,
                    repo=repo,
                    pr_number=pr_number,
                    created_at=created_at,
                )
            except Exception:
                # Best-effort index for search; decision persistence is the source of truth.
                pass
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
