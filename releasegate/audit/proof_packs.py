from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def record_proof_pack_generation(
    *,
    decision_id: str,
    output_format: str,
    bundle_version: str,
    repo: Optional[str] = None,
    pr_number: Optional[int] = None,
    tenant_id: Optional[str] = None,
) -> str:
    """
    Persist proof-pack generation metadata for auditability.
    """
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    created_at = datetime.now(timezone.utc).isoformat()
    proof_pack_id = hashlib.sha256(
        f"{effective_tenant}:{decision_id}:{output_format}:{created_at}".encode("utf-8")
    ).hexdigest()[:32]

    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO audit_proof_packs (
            proof_pack_id, tenant_id, decision_id, repo, pr_number, output_format, bundle_version, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, proof_pack_id) DO NOTHING
        """,
        (
            proof_pack_id,
            effective_tenant,
            decision_id,
            repo,
            pr_number,
            output_format,
            bundle_version,
            created_at,
        ),
    )
    return proof_pack_id
