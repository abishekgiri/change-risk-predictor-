"""ROI Calculator — Phase 9 Commercial Proof.

Converts operational pain points into dollar figures that close deals.

Model
-----
Three value levers:
  1. Incident reduction   — blocked deploys prevent incidents
  2. Audit automation     — decision registry + trace graph eliminates manual prep
  3. Engineer time        — governance overhead drops when every link is enforced

Usage::

    result = calculate_roi(
        team_size=25,
        deploys_per_week=15,
        incidents_per_month=3,
        audit_hours_per_year=160,
    )
    # result["monthly_savings_usd"], result["roi_pct"], result["payback_months"]
"""
from __future__ import annotations

import math
from typing import Any, Dict

# ── Defaults ──────────────────────────────────────────────────────────────────
# These are conservative industry estimates; override via function params.

DEFAULT_HOURLY_RATE_USD = 150          # avg fully-loaded eng cost / hr
DEFAULT_INCIDENT_COST_USD = 5_000      # eng + on-call + customer impact per incident
DEFAULT_AUDIT_PREP_COST_PER_HR = 120   # compliance/eng time during audit

# ReleaseGate effectiveness assumptions (conservative)
INCIDENT_REDUCTION_RATE = 0.30         # 30% of incidents are deploy-caused and preventable
AUDIT_AUTOMATION_RATE   = 0.80         # 80% of manual audit prep hours automated
GOVERNANCE_OVERHEAD_HOURS_PER_DEV_PER_MONTH = 2.0  # hrs/dev/month saved (PR checks, trace hunts)

# Assumed monthly license cost bands
LICENSE_COST_PER_SEAT_USD = 25         # $25/seat/month (typical early pricing)


def calculate_roi(
    *,
    team_size: int,
    deploys_per_week: float,
    incidents_per_month: float,
    audit_hours_per_year: float,
    avg_engineer_hourly_rate: float = DEFAULT_HOURLY_RATE_USD,
    avg_incident_cost: float = DEFAULT_INCIDENT_COST_USD,
    monthly_license_usd: float | None = None,
) -> Dict[str, Any]:
    """Return a full ROI breakdown dict.

    Parameters
    ----------
    team_size              : number of engineers on the team
    deploys_per_week       : production deploys per week
    incidents_per_month    : incidents (any severity) per month
    audit_hours_per_year   : total human-hours spent on compliance audit prep
    avg_engineer_hourly_rate : fully-loaded hourly cost (default $150)
    avg_incident_cost      : fully-loaded cost per incident (default $5 000)
    monthly_license_usd    : override license cost; defaults to seat-based estimate
    """
    team_size = max(1, int(team_size))
    deploys_per_week = max(0.0, float(deploys_per_week))
    incidents_per_month = max(0.0, float(incidents_per_month))
    audit_hours_per_year = max(0.0, float(audit_hours_per_year))

    # ── Lever 1: Incident reduction ──────────────────────────────────────────
    incidents_avoided_per_month = incidents_per_month * INCIDENT_REDUCTION_RATE
    incident_savings_per_month = incidents_avoided_per_month * avg_incident_cost

    # ── Lever 2: Audit automation ─────────────────────────────────────────────
    audit_hours_per_month = audit_hours_per_year / 12.0
    audit_hours_saved_per_month = audit_hours_per_month * AUDIT_AUTOMATION_RATE
    audit_savings_per_month = audit_hours_saved_per_month * DEFAULT_AUDIT_PREP_COST_PER_HR

    # ── Lever 3: Governance overhead reduction ────────────────────────────────
    governance_hours_saved_per_month = team_size * GOVERNANCE_OVERHEAD_HOURS_PER_DEV_PER_MONTH
    governance_savings_per_month = governance_hours_saved_per_month * avg_engineer_hourly_rate

    # ── Total savings ─────────────────────────────────────────────────────────
    total_monthly_savings = (
        incident_savings_per_month
        + audit_savings_per_month
        + governance_savings_per_month
    )

    # ── License cost ──────────────────────────────────────────────────────────
    if monthly_license_usd is None:
        monthly_license_usd = team_size * LICENSE_COST_PER_SEAT_USD

    net_monthly_benefit = total_monthly_savings - monthly_license_usd
    roi_pct = (net_monthly_benefit / monthly_license_usd * 100) if monthly_license_usd > 0 else 0.0
    payback_months = (monthly_license_usd / total_monthly_savings) if total_monthly_savings > 0 else None

    # ── Operational metrics (non-dollar) ──────────────────────────────────────
    deploys_per_month = deploys_per_week * 4.33
    # Approximate blocked risky deploys: 8% of all deploys would have been orphan/non-compliant
    risky_deploys_blocked_per_month = math.ceil(deploys_per_month * 0.08)

    return {
        # Inputs echoed back
        "inputs": {
            "team_size": team_size,
            "deploys_per_week": deploys_per_week,
            "incidents_per_month": incidents_per_month,
            "audit_hours_per_year": audit_hours_per_year,
            "avg_engineer_hourly_rate": avg_engineer_hourly_rate,
            "avg_incident_cost": avg_incident_cost,
            "monthly_license_usd": round(monthly_license_usd, 2),
        },
        # Dollar outputs
        "monthly_savings_usd": round(total_monthly_savings, 2),
        "annual_savings_usd": round(total_monthly_savings * 12, 2),
        "net_monthly_benefit_usd": round(net_monthly_benefit, 2),
        "roi_pct": round(roi_pct, 1),
        "payback_months": round(payback_months, 1) if payback_months else None,
        # Breakdown
        "breakdown": {
            "incident_savings_per_month": round(incident_savings_per_month, 2),
            "audit_savings_per_month": round(audit_savings_per_month, 2),
            "governance_savings_per_month": round(governance_savings_per_month, 2),
        },
        # Operational proof points (for the case study table)
        "operational": {
            "incidents_avoided_per_month": round(incidents_avoided_per_month, 1),
            "audit_hours_saved_per_month": round(audit_hours_saved_per_month, 1),
            "governance_hours_saved_per_month": round(governance_hours_saved_per_month, 1),
            "risky_deploys_blocked_per_month": risky_deploys_blocked_per_month,
        },
    }
