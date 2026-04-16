"""Ops alert dispatcher for ReleaseGate.

Evaluates alert conditions and dispatches to Slack, email, and/or webhook.
Three condition types are evaluated on a configurable schedule:

  STALE_SIGNAL      – risk signal computed_at older than threshold
  CHECKPOINT_MISSED – no signed checkpoint within 36 hours
  DEPLOY_BLOCKED    – a deploy gate blocked a production deployment

Environment variables
---------------------
RELEASEGATE_OPS_ALERT_WEBHOOK_URL   generic webhook (JSON POST)
RELEASEGATE_SLACK_WEBHOOK_URL       Slack incoming-webhook URL
RELEASEGATE_OPS_ALERT_EMAIL_TO      comma-separated recipient list
RELEASEGATE_OPS_ALERT_COOLDOWN      per-key cooldown in seconds (default 3600)
RELEASEGATE_OPS_ALERT_ENABLED       master switch (default true)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_COOLDOWN_LOCK = threading.Lock()
_LAST_SENT: Dict[str, float] = {}
# NOTE: _LAST_SENT is in-process only. In multi-worker deployments (e.g.
# uvicorn --workers N > 1) different worker processes each maintain a
# separate copy, so the cooldown is not enforced across processes.
# For single-worker or Gunicorn single-process deployments this is fine.
# For multi-worker production, set RELEASEGATE_OPS_ALERT_COOLDOWN high
# enough to tolerate duplicate alerts, or run alerts via the scheduler
# (POST /ops/alerts/check) on a single dedicated process.

# Alert level → Slack color sidebar
_SLACK_COLORS = {
    "critical": "#D72638",
    "warning": "#F4A261",
    "info": "#3A86FF",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name) or default)
    except Exception:
        return default


def _cooldown_key(tenant_id: str, alert_type: str, fingerprint: str) -> str:
    raw = f"{tenant_id}:{alert_type}:{fingerprint}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _should_send(key: str) -> bool:
    cooldown = _env_int("RELEASEGATE_OPS_ALERT_COOLDOWN", 3600)
    now = datetime.now(timezone.utc).timestamp()
    with _COOLDOWN_LOCK:
        last = _LAST_SENT.get(key)
        if last is not None and now - last < cooldown:
            return False
        _LAST_SENT[key] = now
        return True


# ---------------------------------------------------------------------------
# Transport layer
# ---------------------------------------------------------------------------

def _send_slack(*, title: str, body: str, level: str, fields: List[Dict[str, str]]) -> Dict[str, Any]:
    webhook = _env("RELEASEGATE_SLACK_WEBHOOK_URL")
    if not webhook:
        return {"ok": False, "transport": "slack", "error": "RELEASEGATE_SLACK_WEBHOOK_URL not set"}

    color = _SLACK_COLORS.get(level, _SLACK_COLORS["warning"])
    attachment = {
        "color": color,
        "title": title,
        "text": body,
        "fields": [{"title": f["title"], "value": f["value"], "short": True} for f in fields],
        "footer": "ReleaseGate Ops",
        "ts": int(datetime.now(timezone.utc).timestamp()),
    }
    payload = {"attachments": [attachment]}
    try:
        resp = requests.post(webhook, json=payload, timeout=8)
        if resp.status_code >= 400:
            return {"ok": False, "transport": "slack", "status_code": resp.status_code, "error": resp.text[:256]}
        return {"ok": True, "transport": "slack"}
    except Exception as exc:
        return {"ok": False, "transport": "slack", "error": str(exc)}


def _send_webhook(*, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
    webhook = _env("RELEASEGATE_OPS_ALERT_WEBHOOK_URL")
    if not webhook:
        return {"ok": False, "transport": "webhook", "error": "RELEASEGATE_OPS_ALERT_WEBHOOK_URL not set"}
    try:
        resp = requests.post(webhook, json=alert_payload, timeout=8)
        if resp.status_code >= 400:
            return {"ok": False, "transport": "webhook", "status_code": resp.status_code, "error": resp.text[:256]}
        return {"ok": True, "transport": "webhook"}
    except Exception as exc:
        return {"ok": False, "transport": "webhook", "error": str(exc)}


def _send_email(*, subject: str, body_text: str, body_html: str) -> Dict[str, Any]:
    recipients_raw = _env("RELEASEGATE_OPS_ALERT_EMAIL_TO")
    if not recipients_raw:
        return {"ok": False, "transport": "email", "error": "RELEASEGATE_OPS_ALERT_EMAIL_TO not set"}
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if not recipients:
        return {"ok": False, "transport": "email", "error": "no valid recipients"}
    try:
        from releasegate.notifications.email_service import send_email
        return send_email(to=recipients, subject=subject, body_html=body_html, body_text=body_text)
    except Exception as exc:
        return {"ok": False, "transport": "email", "error": str(exc)}


# ---------------------------------------------------------------------------
# Public dispatch API
# ---------------------------------------------------------------------------

def dispatch_ops_alert(
    *,
    tenant_id: str,
    alert_type: str,
    level: str = "warning",
    title: str,
    body: str,
    fields: Optional[List[Dict[str, str]]] = None,
    fingerprint: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Dispatch an ops alert to all configured channels.

    Returns a results dict with per-channel outcome.
    Duplicate alerts within the cooldown window are suppressed.
    """
    if _env("RELEASEGATE_OPS_ALERT_ENABLED", "true").lower() in ("false", "0", "no", "off"):
        return {"ok": True, "suppressed": True, "reason": "alerts disabled"}

    key = _cooldown_key(tenant_id, alert_type, fingerprint or body[:64])
    if not _should_send(key):
        return {"ok": True, "suppressed": True, "reason": "cooldown"}

    now = datetime.now(timezone.utc)
    alert_fields = fields or []
    alert_fields_with_defaults = [
        {"title": "Tenant", "value": tenant_id},
        {"title": "Type", "value": alert_type},
        {"title": "Time", "value": now.strftime("%Y-%m-%d %H:%M UTC")},
    ] + alert_fields

    alert_payload: Dict[str, Any] = {
        "alert_type": alert_type,
        "level": level,
        "tenant_id": tenant_id,
        "title": title,
        "body": body,
        "timestamp": now.isoformat(),
        "metadata": metadata or {},
    }

    logger.warning("ops_alert type=%s tenant=%s title=%s", alert_type, tenant_id, title)

    results: Dict[str, Any] = {"ok": True, "channels": []}

    slack_result = _send_slack(title=title, body=body, level=level, fields=alert_fields_with_defaults)
    results["channels"].append(slack_result)

    webhook_result = _send_webhook(alert_payload=alert_payload)
    results["channels"].append(webhook_result)

    email_html = f"""
<html><body>
<h2 style="color:#D72638">{title}</h2>
<p>{body}</p>
<table style="border-collapse:collapse">
{"".join(f'<tr><td style="padding:4px 12px 4px 0;font-weight:bold">{f["title"]}</td><td style="padding:4px">{f["value"]}</td></tr>' for f in alert_fields_with_defaults)}
</table>
<hr><p style="color:#888;font-size:12px">ReleaseGate Ops Alert — {now.strftime("%Y-%m-%d %H:%M UTC")}</p>
</body></html>"""
    email_text = f"{title}\n\n{body}\n\n" + "\n".join(f"{f['title']}: {f['value']}" for f in alert_fields_with_defaults)
    email_result = _send_email(subject=f"[ReleaseGate] {title}", body_text=email_text, body_html=email_html)
    results["channels"].append(email_result)

    delivered_count = sum(1 for c in results["channels"] if c.get("ok") and not c.get("error"))
    results["delivered"] = delivered_count > 0
    return results


# ---------------------------------------------------------------------------
# Condition evaluators
# ---------------------------------------------------------------------------

def check_stale_signal_alert(*, tenant_id: str, storage: Any) -> Optional[Dict[str, Any]]:
    """Alert if the latest risk signal is older than the configured threshold."""
    from releasegate.governance.signal_freshness import signal_freshness_config
    cfg = signal_freshness_config()
    max_age = int(cfg.get("max_age_seconds") or 3600)
    threshold_hours = max(1, max_age * 3 // 3600)  # alert at 3× the reject threshold

    try:
        row = storage.fetchone(
            "SELECT MAX(computed_at) as latest FROM audit_decisions WHERE tenant_id = ?",
            (tenant_id,),
        )
        if not row or not row.get("latest"):
            return None
        latest = datetime.fromisoformat(str(row["latest"]))
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - latest).total_seconds() / 3600
        if age_hours < threshold_hours:
            return None
    except Exception:
        logger.debug("stale signal check failed for tenant %s", tenant_id, exc_info=True)
        return None

    return dispatch_ops_alert(
        tenant_id=tenant_id,
        alert_type="STALE_SIGNAL",
        level="warning",
        title=f"Risk signal stale for {tenant_id}",
        body=f"No risk signals evaluated in {age_hours:.1f} hours. Threshold is {threshold_hours}h.",
        fields=[
            {"title": "Age", "value": f"{age_hours:.1f}h"},
            {"title": "Threshold", "value": f"{threshold_hours}h"},
        ],
        fingerprint=tenant_id,
    )


def check_checkpoint_alert(*, tenant_id: str, storage: Any) -> Optional[Dict[str, Any]]:
    """Alert if no signed checkpoint has been created in the last 36 hours."""
    threshold_hours = 36
    try:
        row = storage.fetchone(
            "SELECT MAX(created_at) as latest, COUNT(*) as cnt FROM audit_checkpoints WHERE tenant_id = ?",
            (tenant_id,),
        )
        if not row or not row.get("latest"):
            # No checkpoints at all — only alert if there are decisions to checkpoint
            decision_row = storage.fetchone(
                "SELECT COUNT(*) as cnt FROM audit_decisions WHERE tenant_id = ?",
                (tenant_id,),
            )
            if not decision_row or (decision_row.get("cnt") or 0) == 0:
                return None
            return dispatch_ops_alert(
                tenant_id=tenant_id,
                alert_type="CHECKPOINT_MISSED",
                level="critical",
                title=f"No checkpoints for {tenant_id}",
                body="Decisions exist but no checkpoint has ever been created. Audit trail is unverifiable.",
                fingerprint=tenant_id,
            )

        latest = datetime.fromisoformat(str(row["latest"]))
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - latest).total_seconds() / 3600
        if age_hours < threshold_hours:
            return None
    except Exception:
        logger.debug("checkpoint check failed for tenant %s", tenant_id, exc_info=True)
        return None

    return dispatch_ops_alert(
        tenant_id=tenant_id,
        alert_type="CHECKPOINT_MISSED",
        level="critical",
        title=f"Checkpoint overdue for {tenant_id}",
        body=f"Last signed checkpoint was {age_hours:.1f} hours ago. Expected cadence is ≤ 24h.",
        fields=[
            {"title": "Last checkpoint", "value": f"{age_hours:.1f}h ago"},
            {"title": "Threshold", "value": f"{threshold_hours}h"},
        ],
        fingerprint=tenant_id,
    )


def check_blocked_deploy_alert(*, tenant_id: str, storage: Any) -> Optional[Dict[str, Any]]:
    """Alert if a production deployment was blocked in the last hour."""
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        row = storage.fetchone(
            """SELECT COUNT(*) as cnt FROM audit_decisions
               WHERE tenant_id = ? AND release_status = 'BLOCKED'
               AND created_at >= ?""",
            (tenant_id, cutoff),
        )
        blocked_count = int((row.get("cnt") or 0) if row else 0)
        if blocked_count == 0:
            return None
    except Exception:
        logger.debug("blocked deploy check failed for tenant %s", tenant_id, exc_info=True)
        return None

    return dispatch_ops_alert(
        tenant_id=tenant_id,
        alert_type="DEPLOY_BLOCKED",
        level="warning",
        title=f"{blocked_count} deployment(s) blocked for {tenant_id}",
        body=f"{blocked_count} release(s) were blocked by policy in the last hour. Review the evidence graph.",
        fields=[
            {"title": "Blocked (1h)", "value": str(blocked_count)},
            {"title": "Action", "value": "Check /audit/evidence"},
        ],
        fingerprint=f"{tenant_id}:{blocked_count}",
    )


def run_all_checks(*, tenant_id: str, storage: Any) -> List[Dict[str, Any]]:
    """Run all three alert condition checks for a tenant. Returns list of dispatched alerts."""
    results = []
    for check_fn in (check_stale_signal_alert, check_checkpoint_alert, check_blocked_deploy_alert):
        result = check_fn(tenant_id=tenant_id, storage=storage)
        if result is not None:
            results.append(result)
    return results
