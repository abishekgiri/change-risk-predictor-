"""Tenant notification preference management."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from releasegate.storage import get_storage_backend


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_notification_preferences(tenant_id: str) -> Dict[str, Any]:
    """Return notification settings for a tenant, creating defaults if missing."""
    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT * FROM tenant_notification_preferences WHERE tenant_id = ?",
        (tenant_id,),
    )
    if row:
        return {
            "tenant_id": row["tenant_id"],
            "email_alerts_enabled": bool(row["email_alerts_enabled"]),
            "email_digest_enabled": bool(row["email_digest_enabled"]),
            "digest_frequency": row["digest_frequency"],
            "alert_recipients": [
                r.strip() for r in (row["alert_recipients"] or "").split(",") if r.strip()
            ],
        }
    return {
        "tenant_id": tenant_id,
        "email_alerts_enabled": True,
        "email_digest_enabled": True,
        "digest_frequency": "weekly",
        "alert_recipients": [],
    }


def update_notification_preferences(
    tenant_id: str,
    *,
    email_alerts_enabled: bool = True,
    email_digest_enabled: bool = True,
    digest_frequency: str = "weekly",
    alert_recipients: List[str] | None = None,
) -> Dict[str, Any]:
    """Create or update notification preferences."""
    if digest_frequency not in ("daily", "weekly", "monthly"):
        raise ValueError("digest_frequency must be daily, weekly, or monthly")
    recipients_csv = ",".join(r.strip() for r in (alert_recipients or []) if r.strip())
    now = _utc_now_iso()
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO tenant_notification_preferences
            (tenant_id, email_alerts_enabled, email_digest_enabled, digest_frequency, alert_recipients, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id) DO UPDATE SET
            email_alerts_enabled = excluded.email_alerts_enabled,
            email_digest_enabled = excluded.email_digest_enabled,
            digest_frequency = excluded.digest_frequency,
            alert_recipients = excluded.alert_recipients,
            updated_at = excluded.updated_at
        """,
        (tenant_id, int(email_alerts_enabled), int(email_digest_enabled), digest_frequency, recipients_csv, now),
    )
    return get_notification_preferences(tenant_id)


def get_notification_recipients(tenant_id: str) -> List[str]:
    """Return email addresses that should receive alerts for this tenant."""
    prefs = get_notification_preferences(tenant_id)
    if not prefs.get("email_alerts_enabled"):
        return []
    return prefs.get("alert_recipients", [])
