from __future__ import annotations

from typing import Any, Dict, List, Optional

from releasegate.audit.attestations import get_release_attestation_by_decision
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
    def search_decisions(
        *,
        limit: int = 20,
        repo: Optional[str] = None,
        status: Optional[str] = None,
        pr: Optional[int] = None,
        jira_issue_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search decisions across repositories and/or by external references.
        """
        init_db()
        storage = get_storage_backend()
        effective_tenant = resolve_tenant_id(tenant_id)

        if jira_issue_key:
            query = """
                SELECT d.*
                FROM audit_decisions d
                JOIN audit_decision_refs r
                  ON d.tenant_id = r.tenant_id AND d.decision_id = r.decision_id
                WHERE d.tenant_id = ?
                  AND r.ref_type = ?
                  AND r.ref_value = ?
            """
            params: List[Any] = [effective_tenant, "jira", str(jira_issue_key).strip()]
            if repo:
                query += " AND d.repo = ?"
                params.append(str(repo).strip())
            if status:
                query += " AND d.release_status = ?"
                params.append(status)
            if pr is not None:
                query += " AND d.pr_number = ?"
                params.append(pr)
            query += " ORDER BY d.created_at DESC LIMIT ?"
            params.append(limit)
            return storage.fetchall(query, params)

        query = "SELECT * FROM audit_decisions WHERE tenant_id = ?"
        params = [effective_tenant]
        if repo:
            query += " AND repo = ?"
            params.append(str(repo).strip())
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

    @staticmethod
    def get_attestation_by_decision(
        decision_id: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return get_release_attestation_by_decision(
            decision_id=decision_id,
            tenant_id=resolve_tenant_id(tenant_id),
        )
