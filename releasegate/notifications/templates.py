"""Email templates for ReleaseGate notifications.

Each function returns ``(subject, html_body, text_body)``.
Templates use inline CSS for maximum email-client compatibility.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

_WRAPPER_START = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f5f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f5f7;padding:32px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e2e8f0;overflow:hidden;">
<tr><td style="background:#0f172a;padding:24px 32px;">
  <span style="color:#ffffff;font-size:20px;font-weight:700;">ReleaseGate</span>
</td></tr>
<tr><td style="padding:32px;">
"""

_WRAPPER_END = """\
</td></tr>
<tr><td style="padding:20px 32px;background:#f8fafc;border-top:1px solid #e2e8f0;">
  <p style="margin:0;font-size:12px;color:#94a3b8;">
    You received this because your organization uses ReleaseGate for release governance.
    Manage preferences in your dashboard notification settings.
  </p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"""


def _wrap(inner_html: str) -> str:
    return f"{_WRAPPER_START}{inner_html}{_WRAPPER_END}"


def _button(label: str, url: str) -> str:
    return (
        f'<a href="{url}" style="display:inline-block;padding:12px 24px;'
        'background:#0f172a;color:#ffffff;text-decoration:none;'
        f'border-radius:6px;font-weight:600;font-size:14px;margin-top:16px;">{label}</a>'
    )


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


def welcome_email(*, org_name: str, onboarding_url: str) -> Tuple[str, str, str]:
    """Welcome email for new signups."""
    subject = f"Welcome to ReleaseGate — {org_name}"
    html = _wrap(f"""\
<h1 style="margin:0 0 16px;font-size:24px;color:#0f172a;">Welcome to ReleaseGate</h1>
<p style="margin:0 0 12px;font-size:15px;color:#334155;line-height:1.6;">
  Your organization <strong>{org_name}</strong> is set up and ready to go.
  Connect your Jira instance to start monitoring release risk in minutes.
</p>
<p style="margin:0 0 8px;font-size:15px;color:#334155;line-height:1.6;">
  Here's what to expect:
</p>
<ol style="margin:0 0 16px;padding-left:20px;font-size:14px;color:#475569;line-height:1.8;">
  <li>Connect Jira (takes 30 seconds)</li>
  <li>Run a historical simulation on your real transitions</li>
  <li>Enable canary mode — observe-only, zero risk</li>
</ol>
{_button("Start Onboarding", onboarding_url)}
""")
    text = (
        f"Welcome to ReleaseGate\n\n"
        f"Your organization {org_name} is set up.\n"
        f"Start onboarding: {onboarding_url}\n"
    )
    return subject, html, text


def risk_alert_email(
    *,
    tenant_id: str,
    risk_title: str,
    risk_description: str,
    action_url: str,
) -> Tuple[str, str, str]:
    """Alert email for detected governance risk."""
    subject = f"[ReleaseGate] Risk Alert: {risk_title}"
    html = _wrap(f"""\
<h1 style="margin:0 0 16px;font-size:22px;color:#dc2626;">Risk Alert</h1>
<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:16px;margin-bottom:16px;">
  <p style="margin:0 0 4px;font-weight:600;color:#991b1b;font-size:15px;">{risk_title}</p>
  <p style="margin:0;color:#7f1d1d;font-size:14px;line-height:1.5;">{risk_description}</p>
</div>
<p style="margin:0;font-size:14px;color:#475569;">
  Review this risk and take action from your governance dashboard.
</p>
{_button("View Dashboard", action_url)}
""")
    text = (
        f"Risk Alert: {risk_title}\n\n"
        f"{risk_description}\n\n"
        f"View: {action_url}\n"
    )
    return subject, html, text


def override_alert_email(
    *,
    tenant_id: str,
    actor: str,
    repo: str,
    reason: str,
    action_url: str,
) -> Tuple[str, str, str]:
    """Alert email when an override spike is detected."""
    subject = f"[ReleaseGate] Override Alert: {repo}"
    html = _wrap(f"""\
<h1 style="margin:0 0 16px;font-size:22px;color:#d97706;">Override Activity Detected</h1>
<table style="width:100%;font-size:14px;color:#334155;line-height:1.6;margin-bottom:16px;" cellpadding="4">
  <tr><td style="font-weight:600;width:100px;">Repository</td><td>{repo}</td></tr>
  <tr><td style="font-weight:600;">Actor</td><td>{actor}</td></tr>
  <tr><td style="font-weight:600;">Reason</td><td>{reason}</td></tr>
</table>
<p style="margin:0;font-size:14px;color:#475569;">
  Override spikes may indicate control fatigue or policy gaps. Review in your dashboard.
</p>
{_button("Review Overrides", action_url)}
""")
    text = (
        f"Override Alert: {repo}\n"
        f"Actor: {actor}\n"
        f"Reason: {reason}\n\n"
        f"Review: {action_url}\n"
    )
    return subject, html, text


def weekly_digest_email(
    *,
    tenant_id: str,
    org_name: str,
    summary: Dict[str, Any],
) -> Tuple[str, str, str]:
    """Weekly governance digest summary."""
    decisions = summary.get("total_decisions", 0)
    blocked = summary.get("blocked_decisions", 0)
    overrides = summary.get("overrides", 0)
    integrity = summary.get("integrity_score", 0)
    alerts = summary.get("active_alerts", 0)
    dashboard_url = summary.get("dashboard_url", "")

    subject = f"[ReleaseGate] Weekly Digest — {org_name}"
    html = _wrap(f"""\
<h1 style="margin:0 0 16px;font-size:22px;color:#0f172a;">Weekly Governance Digest</h1>
<p style="margin:0 0 16px;font-size:14px;color:#64748b;">
  Here's your 7-day governance summary for <strong>{org_name}</strong>.
</p>
<table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
  <tr>
    <td style="padding:12px;text-align:center;background:#f1f5f9;border-radius:6px 0 0 0;">
      <div style="font-size:24px;font-weight:700;color:#0f172a;">{decisions}</div>
      <div style="font-size:12px;color:#64748b;margin-top:4px;">Decisions</div>
    </td>
    <td style="padding:12px;text-align:center;background:#f1f5f9;">
      <div style="font-size:24px;font-weight:700;color:#dc2626;">{blocked}</div>
      <div style="font-size:12px;color:#64748b;margin-top:4px;">Blocked</div>
    </td>
    <td style="padding:12px;text-align:center;background:#f1f5f9;">
      <div style="font-size:24px;font-weight:700;color:#d97706;">{overrides}</div>
      <div style="font-size:12px;color:#64748b;margin-top:4px;">Overrides</div>
    </td>
    <td style="padding:12px;text-align:center;background:#f1f5f9;border-radius:0 6px 0 0;">
      <div style="font-size:24px;font-weight:700;color:#0f172a;">{integrity:.0f}</div>
      <div style="font-size:12px;color:#64748b;margin-top:4px;">Integrity</div>
    </td>
  </tr>
</table>
{"<p style='margin:0 0 16px;font-size:14px;color:#dc2626;font-weight:600;'>" + str(alerts) + " active alerts require attention.</p>" if alerts else ""}
{_button("Open Dashboard", dashboard_url)}
""")
    text = (
        f"Weekly Governance Digest — {org_name}\n\n"
        f"Decisions: {decisions}  |  Blocked: {blocked}  |  "
        f"Overrides: {overrides}  |  Integrity: {integrity:.0f}\n\n"
        f"Dashboard: {dashboard_url}\n"
    )
    return subject, html, text
