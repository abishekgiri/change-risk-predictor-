from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def log_security_event(
    *,
    tenant_id: str,
    principal_id: str,
    auth_method: str,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    init_db()
    storage = get_storage_backend()
    effective_tenant = resolve_tenant_id(tenant_id)
    event_id = uuid.uuid4().hex
    storage.execute(
        """
        INSERT INTO security_audit_events (
            tenant_id, event_id, principal_id, auth_method, action, target_type, target_id, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            effective_tenant,
            event_id,
            principal_id,
            auth_method,
            action,
            target_type,
            target_id,
            json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    return event_id

