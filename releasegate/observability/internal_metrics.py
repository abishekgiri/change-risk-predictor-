from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, Optional
import json
import uuid

from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


_lock = Lock()
_counters_by_tenant = defaultdict(Counter)


def incr(metric: str, value: int = 1, tenant_id: Optional[str] = None) -> None:
    effective_tenant = resolve_tenant_id(tenant_id)
    with _lock:
        _counters_by_tenant[effective_tenant][metric] += int(value)
    try:
        init_db()
        get_storage_backend().execute(
            """
            INSERT INTO metrics_events (tenant_id, event_id, metric_name, metric_value, created_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                effective_tenant,
                uuid.uuid4().hex,
                metric,
                int(value),
                datetime.now(timezone.utc).isoformat(),
                json.dumps({}),
            ),
        )
    except Exception:
        # Metrics persistence should never break enforcement path.
        return


def snapshot(tenant_id: Optional[str] = None, include_tenants: bool = False) -> Dict[str, int]:
    with _lock:
        if tenant_id:
            effective_tenant = resolve_tenant_id(tenant_id)
            return dict(_counters_by_tenant.get(effective_tenant, Counter()))

        total = Counter()
        for tenant_counter in _counters_by_tenant.values():
            total.update(tenant_counter)
        result: Dict[str, int] = dict(total)

        if include_tenants:
            result["_by_tenant"] = {
                tenant: dict(counter)
                for tenant, counter in sorted(_counters_by_tenant.items(), key=lambda item: item[0])
            }
        return result


def reset(tenant_id: Optional[str] = None) -> None:
    with _lock:
        if tenant_id:
            effective_tenant = resolve_tenant_id(tenant_id)
            _counters_by_tenant.pop(effective_tenant, None)
            return
        _counters_by_tenant.clear()
