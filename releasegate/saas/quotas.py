from __future__ import annotations

from typing import Any, Dict, Optional

from releasegate.quota.quota_service import get_tenant_governance_metrics
from releasegate.saas.plans import get_plan_tier
from releasegate.saas.tenants import get_tenant_profile
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


def _usage_percent(*, usage: int, limit: Optional[int]) -> Optional[float]:
    if limit is None or limit <= 0:
        return None
    return round((float(usage) / float(limit)) * 100.0, 2)


def _sum_table_column_bytes(*, tenant_id: str, table: str, column: str) -> int:
    storage = get_storage_backend()
    length_fn = "LENGTH" if storage.name == "sqlite" else "OCTET_LENGTH"
    query = f"SELECT COALESCE(SUM({length_fn}(COALESCE({column}, ''))), 0) AS total FROM {table} WHERE tenant_id = ?"
    try:
        row = storage.fetchone(query, (tenant_id,)) or {}
    except Exception:
        return 0
    try:
        return int(row.get("total") or 0)
    except Exception:
        return 0


def _estimated_storage_bytes(*, tenant_id: str) -> int:
    candidates = [
        ("audit_decisions", "full_decision_json"),
        ("audit_overrides", "reason"),
        ("policy_snapshots", "policy_json"),
        ("tenant_simulation_runs", "result_json"),
        ("governance_daily_metrics", "details_json"),
        ("tenant_policy_snapshot_cache", "snapshot_json"),
    ]
    total = 0
    for table, column in candidates:
        total += _sum_table_column_bytes(tenant_id=tenant_id, table=table, column=column)

    return max(0, int(total))


def get_billing_usage(*, tenant_id: Optional[str]) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)
    profile = get_tenant_profile(tenant_id=effective_tenant)
    plan = get_plan_tier(profile.get("plan"))
    governance_metrics = get_tenant_governance_metrics(tenant_id=effective_tenant)

    decisions_this_month = int(governance_metrics.get("decisions_month") or 0)
    overrides_this_month = int(governance_metrics.get("overrides_month") or 0)

    storage_bytes = _estimated_storage_bytes(tenant_id=effective_tenant)
    storage_mb = round(storage_bytes / (1024 * 1024), 2)
    storage_limit_bytes = (plan.storage_limit_mb * 1024 * 1024) if plan.storage_limit_mb is not None else None

    simulation_runs = 0
    storage = get_storage_backend()
    try:
        row = storage.fetchone(
            """
            SELECT COUNT(1) AS count
            FROM tenant_simulation_runs
            WHERE tenant_id = ?
            """,
            (effective_tenant,),
        ) or {}
        simulation_runs = int(row.get("count") or 0)
    except Exception:
        simulation_runs = 0

    return {
        "tenant_id": effective_tenant,
        "plan": plan.name,
        "status": profile.get("status") or "active",
        "decisions_this_month": decisions_this_month,
        "decision_limit": plan.decision_limit_month,
        "decision_usage_pct": _usage_percent(usage=decisions_this_month, limit=plan.decision_limit_month),
        "overrides_this_month": overrides_this_month,
        "override_limit": plan.override_limit_month,
        "override_usage_pct": _usage_percent(usage=overrides_this_month, limit=plan.override_limit_month),
        "storage_mb": storage_mb,
        "storage_limit_mb": plan.storage_limit_mb,
        "storage_usage_pct": _usage_percent(usage=storage_bytes, limit=storage_limit_bytes),
        "simulation_runs": simulation_runs,
        "simulation_history_days_limit": plan.simulation_history_days,
    }
