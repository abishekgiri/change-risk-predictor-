from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class PlanTier:
    name: str
    decision_limit_month: Optional[int]
    override_limit_month: Optional[int]
    simulation_history_days: int
    storage_limit_mb: Optional[int]
    blocked_list_limit: int


_PLAN_CONFIG: Dict[str, PlanTier] = {
    "starter": PlanTier(
        name="starter",
        decision_limit_month=5000,
        override_limit_month=200,
        simulation_history_days=7,
        storage_limit_mb=512,
        blocked_list_limit=100,
    ),
    "growth": PlanTier(
        name="growth",
        decision_limit_month=50000,
        override_limit_month=2000,
        simulation_history_days=30,
        storage_limit_mb=2048,
        blocked_list_limit=500,
    ),
    "enterprise": PlanTier(
        name="enterprise",
        decision_limit_month=None,
        override_limit_month=None,
        simulation_history_days=365,
        storage_limit_mb=None,
        blocked_list_limit=5000,
    ),
}

DEFAULT_PLAN = "enterprise"


def normalize_plan_tier(value: Optional[str]) -> str:
    plan = str(value or DEFAULT_PLAN).strip().lower()
    if plan not in _PLAN_CONFIG:
        raise ValueError("plan must be one of starter, growth, enterprise")
    return plan


def get_plan_tier(value: Optional[str]) -> PlanTier:
    return _PLAN_CONFIG[normalize_plan_tier(value)]


def get_plan_limits_payload(value: Optional[str]) -> Dict[str, Any]:
    plan = get_plan_tier(value)
    return {
        "plan": plan.name,
        "decision_limit_month": plan.decision_limit_month,
        "override_limit_month": plan.override_limit_month,
        "simulation_history_days": plan.simulation_history_days,
        "storage_limit_mb": plan.storage_limit_mb,
        "blocked_list_limit": plan.blocked_list_limit,
    }


def governance_limits_for_plan(value: Optional[str]) -> Dict[str, Optional[int]]:
    plan = get_plan_tier(value)
    return {
        "max_decisions_per_month": plan.decision_limit_month,
        "max_overrides_per_month": plan.override_limit_month,
    }
