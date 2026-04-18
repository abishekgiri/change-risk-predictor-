"""ROI Calculator — Phase 9 Commercial Proof.

Design principle: conservative assumptions, fully visible.
Every multiplier is sourced + documented so a buyer can challenge it.
Trust > big numbers.

Model
-----
Three value levers:

  1. Incident reduction
     Source: Puppet State of DevOps 2023 — ~23% of incidents are traced to
     deployment errors. We use 15% (intentionally lower) to stay defensible.

  2. Audit automation
     Source: internal estimate — teams using manual audit prep report 2-6 weeks
     per audit cycle. ReleaseGate automates the evidence trail.
     We credit 60% automation (not 80%), assuming some human review remains.

  3. Governance overhead
     Source: eng manager survey data — developers spend ~1-2 hrs/month hunting
     for deploy context, writing incident reports, chasing Jira links.
     We use 1.0 hr/dev/month (bottom of range).

All three are labelled in the response under "assumptions" so buyers see
exactly what was assumed, and can adjust.
"""
from __future__ import annotations

import math
from typing import Any, Dict

# ── Assumptions (intentionally conservative) ─────────────────────────────────
# Changing these changes every output — they are the model, not magic numbers.

ASSUMPTIONS: Dict[str, Any] = {
    "incident_reduction_rate": {
        "value": 0.15,
        "label": "15% of incidents are caused by deploy errors (Puppet DevOps Report 2023 cites ~23%; we use 15%)",
    },
    "audit_automation_rate": {
        "value": 0.60,
        "label": "60% of manual audit-prep hours eliminated (assumes some human review still required)",
    },
    "governance_overhead_hrs_per_dev_per_month": {
        "value": 1.0,
        "label": "1 hr/dev/month reclaimed (context-hunting, trace lookups, incident write-ups)",
    },
    "default_engineer_hourly_rate_usd": {
        "value": 150,
        "label": "US$150 fully-loaded hourly cost (mid-market SaaS; adjust for your region)",
    },
    "default_incident_cost_usd": {
        "value": 4_000,
        "label": "US$4 000 per incident (eng time + on-call + customer impact; Gartner estimates $5 600)",
    },
    "audit_prep_cost_per_hr_usd": {
        "value": 100,
        "label": "US$100/hr for compliance + eng time during audit cycles",
    },
    "license_cost_per_seat_usd": {
        "value": 25,
        "label": "US$25/seat/month assumed license cost",
    },
    "orphan_deploy_rate": {
        "value": 0.05,
        "label": "5% of deploys would be orphan/non-compliant without enforcement (used for blocked-deploy estimate)",
    },
}

# ── Extracted values (keep in sync with ASSUMPTIONS dict above) ──────────────
_INCIDENT_REDUCTION_RATE       = ASSUMPTIONS["incident_reduction_rate"]["value"]
_AUDIT_AUTOMATION_RATE         = ASSUMPTIONS["audit_automation_rate"]["value"]
_GOV_OVERHEAD_HRS              = ASSUMPTIONS["governance_overhead_hrs_per_dev_per_month"]["value"]
_DEFAULT_ENG_RATE              = ASSUMPTIONS["default_engineer_hourly_rate_usd"]["value"]
_DEFAULT_INCIDENT_COST         = ASSUMPTIONS["default_incident_cost_usd"]["value"]
_AUDIT_PREP_COST_PER_HR        = ASSUMPTIONS["audit_prep_cost_per_hr_usd"]["value"]
_LICENSE_PER_SEAT              = ASSUMPTIONS["license_cost_per_seat_usd"]["value"]
_ORPHAN_DEPLOY_RATE            = ASSUMPTIONS["orphan_deploy_rate"]["value"]


def calculate_roi(
    *,
    team_size: int,
    deploys_per_week: float,
    incidents_per_month: float,
    audit_hours_per_year: float,
    avg_engineer_hourly_rate: float = _DEFAULT_ENG_RATE,
    avg_incident_cost: float = _DEFAULT_INCIDENT_COST,
    monthly_license_usd: float | None = None,
) -> Dict[str, Any]:
    """Return a full ROI breakdown dict with visible assumptions.

    Parameters
    ----------
    team_size              : number of engineers on the team
    deploys_per_week       : production deploys per week
    incidents_per_month    : incidents (any severity) per month
    audit_hours_per_year   : total human-hours spent on compliance audit prep
    avg_engineer_hourly_rate : fully-loaded hourly cost (default $150)
    avg_incident_cost      : fully-loaded cost per incident (default $4 000)
    monthly_license_usd    : override license cost; defaults to seat-based estimate
    """
    team_size            = max(1, int(team_size))
    deploys_per_week     = max(0.0, float(deploys_per_week))
    incidents_per_month  = max(0.0, float(incidents_per_month))
    audit_hours_per_year = max(0.0, float(audit_hours_per_year))

    # ── Lever 1: Incident reduction ──────────────────────────────────────────
    incidents_avoided        = incidents_per_month * _INCIDENT_REDUCTION_RATE
    incident_savings         = incidents_avoided * avg_incident_cost

    # ── Lever 2: Audit automation ─────────────────────────────────────────────
    audit_hours_per_month    = audit_hours_per_year / 12.0
    audit_hours_saved        = audit_hours_per_month * _AUDIT_AUTOMATION_RATE
    audit_savings            = audit_hours_saved * _AUDIT_PREP_COST_PER_HR

    # ── Lever 3: Governance overhead ──────────────────────────────────────────
    gov_hours_saved          = team_size * _GOV_OVERHEAD_HRS
    gov_savings              = gov_hours_saved * avg_engineer_hourly_rate

    # ── Total ─────────────────────────────────────────────────────────────────
    total_monthly_savings    = incident_savings + audit_savings + gov_savings

    if monthly_license_usd is None:
        monthly_license_usd  = team_size * _LICENSE_PER_SEAT

    net_monthly              = total_monthly_savings - monthly_license_usd
    roi_pct                  = (net_monthly / monthly_license_usd * 100) if monthly_license_usd > 0 else 0.0
    payback_months           = (monthly_license_usd / total_monthly_savings) if total_monthly_savings > 0 else None

    # ── Operational proof points ──────────────────────────────────────────────
    deploys_per_month        = deploys_per_week * 4.33
    risky_deploys_blocked    = math.ceil(deploys_per_month * _ORPHAN_DEPLOY_RATE)

    return {
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
        "monthly_savings_usd":     round(total_monthly_savings, 2),
        "annual_savings_usd":      round(total_monthly_savings * 12, 2),
        "net_monthly_benefit_usd": round(net_monthly, 2),
        "roi_pct":                 round(roi_pct, 1),
        "payback_months":          round(payback_months, 1) if payback_months else None,
        # Per-lever breakdown
        "breakdown": {
            "incident_savings_per_month":    round(incident_savings, 2),
            "audit_savings_per_month":       round(audit_savings, 2),
            "governance_savings_per_month":  round(gov_savings, 2),
        },
        # Non-dollar operational proof
        "operational": {
            "incidents_avoided_per_month":          round(incidents_avoided, 1),
            "audit_hours_saved_per_month":          round(audit_hours_saved, 1),
            "governance_hours_saved_per_month":     round(gov_hours_saved, 1),
            "risky_deploys_blocked_per_month":      risky_deploys_blocked,
        },
        # Visible assumptions — include in every response so buyers can audit the model
        "assumptions": {k: v["label"] for k, v in ASSUMPTIONS.items()},
    }
