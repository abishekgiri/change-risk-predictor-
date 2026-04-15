"""Stripe billing integration for ReleaseGate.

Uses raw HTTP requests against the Stripe API — no ``stripe`` SDK dependency.

Environment variables:
    STRIPE_SECRET_KEY         : sk_test_... or sk_live_...
    STRIPE_WEBHOOK_SECRET     : whsec_...
    STRIPE_STARTER_PRICE_ID   : Stripe Price ID for starter plan
    STRIPE_GROWTH_PRICE_ID    : Stripe Price ID for growth plan
    STRIPE_ENTERPRISE_PRICE_ID: Stripe Price ID for enterprise plan
    RELEASEGATE_BASE_URL      : Base URL for success/cancel redirects
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests as http_client

from releasegate.storage import get_storage_backend

logger = logging.getLogger(__name__)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _base_url() -> str:
    return _env("RELEASEGATE_BASE_URL", "https://app.releasegate.io")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_stripe_configured() -> bool:
    return bool(_env("STRIPE_SECRET_KEY"))


# ---------------------------------------------------------------------------
# Stripe HTTP helpers
# ---------------------------------------------------------------------------

def _stripe_request(
    method: str,
    endpoint: str,
    data: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    secret_key = _env("STRIPE_SECRET_KEY")
    if not secret_key:
        raise RuntimeError("STRIPE_SECRET_KEY not configured")
    resp = http_client.request(
        method,
        f"https://api.stripe.com/v1{endpoint}",
        auth=(secret_key, ""),
        data=data,
        timeout=15,
    )
    if resp.status_code >= 400:
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        error_msg = body.get("error", {}).get("message", resp.text[:256])
        raise RuntimeError(f"Stripe API error ({resp.status_code}): {error_msg}")
    return resp.json()


def _get_price_id(plan: str) -> str:
    mapping = {
        "starter": _env("STRIPE_STARTER_PRICE_ID"),
        "growth": _env("STRIPE_GROWTH_PRICE_ID"),
        "enterprise": _env("STRIPE_ENTERPRISE_PRICE_ID"),
    }
    price_id = mapping.get(plan, "")
    if not price_id:
        raise ValueError(f"No Stripe price configured for plan: {plan}")
    return price_id


# ---------------------------------------------------------------------------
# Customer management
# ---------------------------------------------------------------------------

def _ensure_billing_row(tenant_id: str) -> None:
    now = _utc_now_iso()
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO tenant_billing_info
            (tenant_id, current_plan, subscription_status, created_at, updated_at)
        VALUES (?, 'starter', 'none', ?, ?)
        ON CONFLICT(tenant_id) DO NOTHING
        """,
        (tenant_id, now, now),
    )


def _get_or_create_customer(tenant_id: str) -> str:
    """Get existing Stripe customer ID or create a new one."""
    _ensure_billing_row(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT stripe_customer_id FROM tenant_billing_info WHERE tenant_id = ?",
        (tenant_id,),
    )
    if row and row["stripe_customer_id"]:
        return row["stripe_customer_id"]

    result = _stripe_request("POST", "/customers", {
        "metadata[tenant_id]": tenant_id,
        "description": f"ReleaseGate tenant {tenant_id}",
    })
    customer_id = result["id"]
    storage.execute(
        "UPDATE tenant_billing_info SET stripe_customer_id = ?, updated_at = ? WHERE tenant_id = ?",
        (customer_id, _utc_now_iso(), tenant_id),
    )
    return customer_id


# ---------------------------------------------------------------------------
# Checkout / Portal
# ---------------------------------------------------------------------------

def create_checkout_session(*, tenant_id: str, plan: str) -> Dict[str, Any]:
    """Create a Stripe Checkout session for plan subscription."""
    price_id = _get_price_id(plan)
    customer_id = _get_or_create_customer(tenant_id)
    base = _base_url()
    result = _stripe_request("POST", "/checkout/sessions", {
        "customer": customer_id,
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": f"{base}/billing?tenant_id={tenant_id}&checkout=success",
        "cancel_url": f"{base}/billing?tenant_id={tenant_id}&checkout=cancel",
        "metadata[tenant_id]": tenant_id,
        "metadata[plan]": plan,
    })
    return {"checkout_url": result.get("url", ""), "session_id": result["id"]}


def create_portal_session(*, tenant_id: str) -> Dict[str, Any]:
    """Create a Stripe Customer Portal session."""
    customer_id = _get_or_create_customer(tenant_id)
    base = _base_url()
    result = _stripe_request("POST", "/billing_portal/sessions", {
        "customer": customer_id,
        "return_url": f"{base}/billing?tenant_id={tenant_id}",
    })
    return {"portal_url": result.get("url", "")}


# ---------------------------------------------------------------------------
# Webhook handling
# ---------------------------------------------------------------------------

def verify_webhook_signature(payload: bytes, sig_header: str) -> bool:
    """Verify Stripe webhook signature (v1 scheme)."""
    secret = _env("STRIPE_WEBHOOK_SECRET")
    if not secret:
        logger.warning("STRIPE_WEBHOOK_SECRET not set — skipping signature verification")
        return True

    try:
        parts = dict(item.split("=", 1) for item in sig_header.split(","))
        timestamp = parts.get("t", "")
        signature = parts.get("v1", "")
        if not timestamp or not signature:
            return False

        if abs(time.time() - int(timestamp)) > 300:
            return False

        signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
        expected = hmac.new(
            secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


def handle_webhook_event(payload: bytes, sig_header: str) -> Dict[str, Any]:
    """Process a Stripe webhook event."""
    if not verify_webhook_signature(payload, sig_header):
        return {"ok": False, "error": "Invalid signature"}

    import json
    event = json.loads(payload)
    event_type = event.get("type", "")
    data_object = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        return _handle_checkout_completed(data_object)
    elif event_type == "customer.subscription.updated":
        return _handle_subscription_updated(data_object)
    elif event_type == "customer.subscription.deleted":
        return _handle_subscription_deleted(data_object)
    elif event_type == "invoice.payment_failed":
        return _handle_payment_failed(data_object)

    return {"ok": True, "event_type": event_type, "action": "ignored"}


def _handle_checkout_completed(session: Dict[str, Any]) -> Dict[str, Any]:
    tenant_id = (session.get("metadata") or {}).get("tenant_id", "")
    plan = (session.get("metadata") or {}).get("plan", "growth")
    subscription_id = session.get("subscription", "")
    if not tenant_id:
        return {"ok": False, "error": "Missing tenant_id in metadata"}

    storage = get_storage_backend()
    _ensure_billing_row(tenant_id)
    storage.execute(
        """
        UPDATE tenant_billing_info SET
            stripe_subscription_id = ?,
            subscription_status = 'active',
            current_plan = ?,
            updated_at = ?
        WHERE tenant_id = ?
        """,
        (subscription_id, plan, _utc_now_iso(), tenant_id),
    )

    _update_tenant_plan(tenant_id, plan)
    return {"ok": True, "action": "subscription_activated", "tenant_id": tenant_id}


def _handle_subscription_updated(subscription: Dict[str, Any]) -> Dict[str, Any]:
    customer_id = subscription.get("customer", "")
    status = subscription.get("status", "")
    tenant_id = _tenant_id_from_customer(customer_id)
    if not tenant_id:
        return {"ok": True, "action": "ignored_unknown_customer"}

    storage = get_storage_backend()
    storage.execute(
        "UPDATE tenant_billing_info SET subscription_status = ?, updated_at = ? WHERE tenant_id = ?",
        (status, _utc_now_iso(), tenant_id),
    )
    return {"ok": True, "action": "subscription_updated", "tenant_id": tenant_id}


def _handle_subscription_deleted(subscription: Dict[str, Any]) -> Dict[str, Any]:
    customer_id = subscription.get("customer", "")
    tenant_id = _tenant_id_from_customer(customer_id)
    if not tenant_id:
        return {"ok": True, "action": "ignored_unknown_customer"}

    storage = get_storage_backend()
    storage.execute(
        """
        UPDATE tenant_billing_info SET
            subscription_status = 'canceled',
            current_plan = 'starter',
            updated_at = ?
        WHERE tenant_id = ?
        """,
        (_utc_now_iso(), tenant_id),
    )
    _update_tenant_plan(tenant_id, "starter")
    return {"ok": True, "action": "subscription_canceled", "tenant_id": tenant_id}


def _handle_payment_failed(invoice: Dict[str, Any]) -> Dict[str, Any]:
    customer_id = invoice.get("customer", "")
    tenant_id = _tenant_id_from_customer(customer_id)
    if not tenant_id:
        return {"ok": True, "action": "ignored_unknown_customer"}

    storage = get_storage_backend()
    storage.execute(
        "UPDATE tenant_billing_info SET subscription_status = 'past_due', updated_at = ? WHERE tenant_id = ?",
        (_utc_now_iso(), tenant_id),
    )
    return {"ok": True, "action": "payment_failed", "tenant_id": tenant_id}


def _tenant_id_from_customer(customer_id: str) -> Optional[str]:
    if not customer_id:
        return None
    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT tenant_id FROM tenant_billing_info WHERE stripe_customer_id = ?",
        (customer_id,),
    )
    return row["tenant_id"] if row else None


def _update_tenant_plan(tenant_id: str, plan: str) -> None:
    """Sync plan tier to tenant_admin_profiles."""
    storage = get_storage_backend()
    storage.execute(
        "UPDATE tenant_admin_profiles SET plan_tier = ?, updated_at = ? WHERE tenant_id = ?",
        (plan, _utc_now_iso(), tenant_id),
    )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_subscription_status(tenant_id: str) -> Dict[str, Any]:
    """Return current subscription info for a tenant."""
    _ensure_billing_row(tenant_id)
    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT * FROM tenant_billing_info WHERE tenant_id = ?",
        (tenant_id,),
    )
    if not row:
        return {
            "tenant_id": tenant_id,
            "subscription_status": "none",
            "current_plan": "starter",
        }
    return {
        "tenant_id": row["tenant_id"],
        "stripe_customer_id": row["stripe_customer_id"],
        "subscription_status": row["subscription_status"],
        "current_plan": row["current_plan"],
        "billing_email": row["billing_email"],
        "trial_ends_at": row["trial_ends_at"],
    }
