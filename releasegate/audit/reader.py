from __future__ import annotations

from typing import Any, Dict, List, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


class AuditReader:
    """
    Read-only access to tenant-scoped audit logs.
    """

    @staticmethod
    def list_decisions(
        repo: str,
        limit: int = 20,
        status: Optional[str] = None,
        pr: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        init_db()
        storage = get_storage_backend()
        effective_tenant = resolve_tenant_id(tenant_id)

        query = "SELECT * FROM audit_decisions WHERE tenant_id = ? AND repo = ?"
        params: List[Any] = [effective_tenant, repo]
        if status:
            query += " AND release_status = ?"
            params.append(status)
        if pr is not None:
            query += " AND pr_number = ?"
            params.append(pr)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return storage.fetchall(query, params)

    @staticmethod
    def get_decision(decision_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        init_db()
        storage = get_storage_backend()
        effective_tenant = resolve_tenant_id(tenant_id)
        return storage.fetchone(
            "SELECT * FROM audit_decisions WHERE tenant_id = ? AND decision_id = ?",
            (effective_tenant, decision_id),
        )

    @staticmethod
    def get_decision_by_evaluation_key(
        evaluation_key: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        init_db()
        storage = get_storage_backend()
        effective_tenant = resolve_tenant_id(tenant_id)
        return storage.fetchone(
            "SELECT * FROM audit_decisions WHERE tenant_id = ? AND evaluation_key = ?",
            (effective_tenant, evaluation_key),
        )

    @staticmethod
    def get_policy_bundle(
        policy_bundle_hash: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        from releasegate.audit.policy_bundles import get_policy_bundle

        return get_policy_bundle(tenant_id=tenant_id, policy_bundle_hash=policy_bundle_hash)

    @staticmethod
    def get_latest_active_policy_bundle(tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        from releasegate.audit.policy_bundles import get_latest_active_policy_bundle

        return get_latest_active_policy_bundle(tenant_id=tenant_id)
