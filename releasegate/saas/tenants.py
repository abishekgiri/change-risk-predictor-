from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from releasegate.quota.quota_service import (
    get_tenant_governance_settings,
    update_tenant_governance_settings,
)
from releasegate.saas.plans import (
    DEFAULT_PLAN,
    get_plan_limits_payload,
    governance_limits_for_plan,
    normalize_plan_tier,
)
from releasegate.security.api_keys import create_api_key, list_api_keys, rotate_api_key
from releasegate.security.security_state_service import set_tenant_security_state
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.tenants.keys import rotate_tenant_signing_key

TENANT_STATUS_ACTIVE = "active"
TENANT_STATUS_LOCKED = "locked"
TENANT_STATUS_THROTTLED = "throttled"

_ROLE_VALUES = {"owner", "admin", "operator", "auditor", "viewer"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_region(value: Optional[str]) -> str:
    region = str(value or "us-east").strip().lower()
    return region or "us-east"


def _normalize_status(value: Optional[str]) -> str:
    status = str(value or TENANT_STATUS_ACTIVE).strip().lower()
    if status not in {TENANT_STATUS_ACTIVE, TENANT_STATUS_LOCKED, TENANT_STATUS_THROTTLED}:
        raise ValueError("status must be one of active, locked, throttled")
    return status


def _status_from_security_state(value: Optional[str]) -> str:
    state = str(value or "normal").strip().lower()
    if state == "locked":
        return TENANT_STATUS_LOCKED
    if state == "throttled":
        return TENANT_STATUS_THROTTLED
    return TENANT_STATUS_ACTIVE


def _security_state_from_status(status: str) -> str:
    if status == TENANT_STATUS_LOCKED:
        return "locked"
    if status == TENANT_STATUS_THROTTLED:
        return "throttled"
    return "normal"


def _normalize_role(role: str) -> str:
    normalized = str(role or "").strip().lower()
    if normalized not in _ROLE_VALUES:
        raise ValueError("role must be one of owner, admin, operator, auditor, viewer")
    return normalized


def _ensure_profile_row(*, tenant_id: str, now_iso: str) -> None:
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO tenant_admin_profiles (
            tenant_id,
            org_name,
            plan_tier,
            region,
            created_at,
            updated_at,
            created_by,
            updated_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id) DO NOTHING
        """,
        (
            tenant_id,
            tenant_id,
            DEFAULT_PLAN,
            "us-east",
            now_iso,
            now_iso,
            "system",
            "system",
        ),
    )


def ensure_tenant_profile_row(
    *,
    tenant_id: str,
    now_iso: Optional[str] = None,
) -> None:
    effective_tenant = resolve_tenant_id(tenant_id)
    _ensure_profile_row(
        tenant_id=effective_tenant,
        now_iso=now_iso or _utc_now_iso(),
    )


def _load_role_assignments(*, tenant_id: str) -> List[Dict[str, Any]]:
    storage = get_storage_backend()
    rows = storage.fetchall(
        """
        SELECT actor_id, role, assigned_by, assigned_at
        FROM tenant_role_assignments
        WHERE tenant_id = ?
        ORDER BY actor_id ASC, role ASC
        """,
        (tenant_id,),
    )
    by_actor: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        actor_id = str(row.get("actor_id") or "").strip()
        if not actor_id:
            continue
        entry = by_actor.setdefault(
            actor_id,
            {
                "actor_id": actor_id,
                "roles": [],
                "last_assigned_at": row.get("assigned_at"),
                "assigned_by": row.get("assigned_by"),
            },
        )
        role = str(row.get("role") or "").strip().lower()
        if role and role not in entry["roles"]:
            entry["roles"].append(role)
        assigned_at = row.get("assigned_at")
        if assigned_at and (entry["last_assigned_at"] or "") < str(assigned_at):
            entry["last_assigned_at"] = assigned_at
            entry["assigned_by"] = row.get("assigned_by")
    return list(by_actor.values())


def get_tenant_profile(*, tenant_id: Optional[str]) -> Dict[str, Any]:

    effective_tenant = resolve_tenant_id(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, org_name, plan_tier, region, created_at, updated_at, created_by, updated_by
        FROM tenant_admin_profiles
        WHERE tenant_id = ?
        LIMIT 1
        """,
        (effective_tenant,),
    ) or {}

    plan_tier = normalize_plan_tier(row.get("plan_tier"))
    settings = get_tenant_governance_settings(tenant_id=effective_tenant)
    status = _status_from_security_state(settings.get("security_state"))
    roles = _load_role_assignments(tenant_id=effective_tenant)

    return {
        "tenant_id": effective_tenant,
        "name": str(row.get("org_name") or effective_tenant),
        "plan": plan_tier,
        "region": str(row.get("region") or "us-east"),
        "status": status,
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "updated_by": row.get("updated_by"),
        "roles": roles,
        "limits": {
            **get_plan_limits_payload(plan_tier),
            "quota_enforcement_mode": settings.get("quota_enforcement_mode"),
        },
    }


def warm_known_tenant_rows_for_startup(*, limit: int = 50) -> Dict[str, Any]:
    from releasegate.governance.dashboard_metrics import list_dashboard_rollup_warmup_tenants
    from releasegate.quota.quota_service import ensure_tenant_governance_settings_row

    now_iso = _utc_now_iso()
    tenants = list_dashboard_rollup_warmup_tenants(limit=limit)
    warmed: List[str] = []
    failed: List[Dict[str, str]] = []

    for tenant_id in tenants:
        try:
            ensure_tenant_profile_row(tenant_id=tenant_id, now_iso=now_iso)
            ensure_tenant_governance_settings_row(tenant_id=tenant_id, now_iso=now_iso)
            warmed.append(tenant_id)
        except Exception as exc:
            failed.append({"tenant_id": tenant_id, "error": str(exc)})

    return {
        "tenants_discovered": len(tenants),
        "tenants_warmed": len(warmed),
        "tenants_failed": len(failed),
        "warmed_tenants": warmed,
        "failed_tenants": failed,
    }


def create_tenant_profile(
    *,
    tenant_id: Optional[str],
    name: Optional[str],
    plan: Optional[str],
    region: Optional[str],
    actor_id: Optional[str],
) -> Dict[str, Any]:

    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_plan = normalize_plan_tier(plan)
    normalized_region = _normalize_region(region)
    normalized_name = str(name or effective_tenant).strip() or effective_tenant
    actor = str(actor_id or "system").strip() or "system"
    now_iso = _utc_now_iso()
    storage = get_storage_backend()

    with storage.transaction():
        _ensure_profile_row(tenant_id=effective_tenant, now_iso=now_iso)
        current = storage.fetchone(
            """
            SELECT created_at, created_by
            FROM tenant_admin_profiles
            WHERE tenant_id = ?
            LIMIT 1
            """,
            (effective_tenant,),
        ) or {}
        created_at = str(current.get("created_at") or now_iso)
        created_by = str(current.get("created_by") or actor)

        storage.execute(
            """
            UPDATE tenant_admin_profiles
            SET org_name = ?,
                plan_tier = ?,
                region = ?,
                created_at = ?,
                updated_at = ?,
                created_by = ?,
                updated_by = ?
            WHERE tenant_id = ?
            """,
            (
                normalized_name,
                normalized_plan,
                normalized_region,
                created_at,
                now_iso,
                created_by,
                actor,
                effective_tenant,
            ),
        )

    plan_limits = governance_limits_for_plan(normalized_plan)
    update_tenant_governance_settings(
        tenant_id=effective_tenant,
        max_decisions_per_month=plan_limits.get("max_decisions_per_month"),
        max_overrides_per_month=plan_limits.get("max_overrides_per_month"),
        updated_by=actor,
    )

    return get_tenant_profile(tenant_id=effective_tenant)


def set_tenant_status(
    *,
    tenant_id: Optional[str],
    status: str,
    reason: Optional[str],
    actor_id: Optional[str],
    source: str = "tenant_admin_panel",
) -> Dict[str, Any]:
    normalized_status = _normalize_status(status)
    effective_tenant = resolve_tenant_id(tenant_id)

    set_tenant_security_state(
        tenant_id=effective_tenant,
        to_state=_security_state_from_status(normalized_status),
        reason=reason or f"tenant_status:{normalized_status}",
        source=source,
        actor=actor_id,
        metadata={"status": normalized_status},
    )
    return get_tenant_profile(tenant_id=effective_tenant)


def assign_tenant_role(
    *,
    tenant_id: Optional[str],
    actor_id: str,
    role: str,
    action: str = "assign",
    assigned_by: Optional[str],
) -> Dict[str, Any]:

    effective_tenant = resolve_tenant_id(tenant_id)
    normalized_actor = str(actor_id or "").strip()
    if not normalized_actor:
        raise ValueError("actor_id is required")
    normalized_role = _normalize_role(role)
    normalized_action = str(action or "assign").strip().lower()
    if normalized_action not in {"assign", "remove"}:
        raise ValueError("action must be assign or remove")

    now_iso = _utc_now_iso()
    operator = str(assigned_by or "system").strip() or "system"
    storage = get_storage_backend()

    with storage.transaction():
        _ensure_profile_row(tenant_id=effective_tenant, now_iso=now_iso)
        if normalized_action == "assign":
            storage.execute(
                """
                INSERT INTO tenant_role_assignments (
                    tenant_id,
                    actor_id,
                    role,
                    assigned_by,
                    assigned_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, actor_id, role) DO UPDATE SET
                    assigned_by = excluded.assigned_by,
                    assigned_at = excluded.assigned_at
                """,
                (effective_tenant, normalized_actor, normalized_role, operator, now_iso),
            )
        else:
            storage.execute(
                """
                DELETE FROM tenant_role_assignments
                WHERE tenant_id = ? AND actor_id = ? AND role = ?
                """,
                (effective_tenant, normalized_actor, normalized_role),
            )

    return get_tenant_profile(tenant_id=effective_tenant)


def rotate_tenant_keys(
    *,
    tenant_id: Optional[str],
    actor_id: Optional[str],
    rotate_signing_key: bool = True,
    rotate_api_key_enabled: bool = True,
    api_key_id: Optional[str] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    principal_id = str(actor_id or "system").strip() or "system"

    if not rotate_signing_key and not rotate_api_key_enabled:
        raise ValueError("at least one key type must be selected for rotation")

    rotated_signing_key_id: Optional[str] = None
    rotated_api_key_id: Optional[str] = None
    api_key_created = False

    if rotate_signing_key:
        signing = rotate_tenant_signing_key(
            tenant_id=effective_tenant,
            created_by=principal_id,
        )
        rotated_signing_key_id = str(signing.get("key_id") or "").strip() or None

    if rotate_api_key_enabled:
        candidate_key_id = str(api_key_id or "").strip() or None
        if not candidate_key_id:
            keys = list_api_keys(tenant_id=effective_tenant)
            for item in keys:
                if item.get("revoked_at"):
                    continue
                if int(item.get("is_enabled") or 0) != 1:
                    continue
                candidate_key_id = str(item.get("key_id") or "").strip() or None
                if candidate_key_id:
                    break

        if candidate_key_id:
            rotated = rotate_api_key(
                tenant_id=effective_tenant,
                key_id=candidate_key_id,
                rotated_by=principal_id,
            )
            if rotated:
                rotated_api_key_id = str(rotated.get("key_id") or "").strip() or None
        else:
            created = create_api_key(
                tenant_id=effective_tenant,
                name="tenant-admin-rotated",
                roles=["operator"],
                scopes=["enforcement:write", "policy:read"],
                created_by=principal_id,
            )
            rotated_api_key_id = str(created.get("key_id") or "").strip() or None
            api_key_created = True

    return {
        "tenant_id": effective_tenant,
        "rotated_signing_key_id": rotated_signing_key_id,
        "rotated_api_key_id": rotated_api_key_id,
        "api_key_created": api_key_created,
    }
