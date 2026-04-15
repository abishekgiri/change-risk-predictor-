"""Multi-provider email notification service.

Supports SMTP, SendGrid, Resend, and Postmark transports.

Environment variables:
    RELEASEGATE_EMAIL_PROVIDER  : smtp | sendgrid | resend | postmark  (default: log-only)
    RELEASEGATE_EMAIL_FROM      : sender address
    RELEASEGATE_EMAIL_FROM_NAME : sender display name (default: ReleaseGate)

SMTP:
    SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD, SMTP_USE_TLS (default true)

API providers:
    SENDGRID_API_KEY, RESEND_API_KEY, POSTMARK_SERVER_TOKEN
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Union

import requests

logger = logging.getLogger(__name__)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _from_address() -> str:
    return _env("RELEASEGATE_EMAIL_FROM", "noreply@releasegate.io")


def _from_name() -> str:
    return _env("RELEASEGATE_EMAIL_FROM_NAME", "ReleaseGate")


def _normalize_recipients(to: Union[str, List[str]]) -> List[str]:
    if isinstance(to, str):
        return [to]
    return list(to)


# ---------------------------------------------------------------------------
# SMTP transport
# ---------------------------------------------------------------------------

def _send_smtp(
    *,
    to: Union[str, List[str]],
    subject: str,
    body_html: str,
    body_text: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> Dict[str, Any]:
    host = _env("SMTP_HOST")
    port = int(_env("SMTP_PORT", "587"))
    user = _env("SMTP_USER")
    password = _env("SMTP_PASSWORD")
    use_tls = _env("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")

    if not host:
        return {"ok": False, "provider": "smtp", "error": "SMTP_HOST not configured"}

    recipients = _normalize_recipients(to)
    msg = MIMEMultipart("alternative")
    msg["From"] = f"{_from_name()} <{_from_address()}>"
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to

    if body_text:
        msg.attach(MIMEText(body_text, "plain", "utf-8"))
    msg.attach(MIMEText(body_html, "html", "utf-8"))

    try:
        if use_tls:
            server = smtplib.SMTP(host, port, timeout=15)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port, timeout=15)
        if user and password:
            server.login(user, password)
        server.sendmail(_from_address(), recipients, msg.as_string())
        server.quit()
        return {"ok": True, "provider": "smtp", "delivered": True}
    except Exception as exc:
        logger.error("SMTP send failed: %s", exc)
        return {"ok": False, "provider": "smtp", "error": str(exc)}


# ---------------------------------------------------------------------------
# SendGrid transport
# ---------------------------------------------------------------------------

def _send_sendgrid(
    *,
    to: Union[str, List[str]],
    subject: str,
    body_html: str,
    body_text: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> Dict[str, Any]:
    api_key = _env("SENDGRID_API_KEY")
    if not api_key:
        return {"ok": False, "provider": "sendgrid", "error": "SENDGRID_API_KEY not configured"}

    recipients = _normalize_recipients(to)
    personalizations = [{"to": [{"email": addr} for addr in recipients]}]
    content = [{"type": "text/html", "value": body_html}]
    if body_text:
        content.insert(0, {"type": "text/plain", "value": body_text})

    payload: Dict[str, Any] = {
        "personalizations": personalizations,
        "from": {"email": _from_address(), "name": _from_name()},
        "subject": subject,
        "content": content,
    }
    if reply_to:
        payload["reply_to"] = {"email": reply_to}

    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=15,
        )
        if resp.status_code >= 400:
            return {"ok": False, "provider": "sendgrid", "error": resp.text[:512]}
        return {"ok": True, "provider": "sendgrid", "delivered": True}
    except Exception as exc:
        logger.error("SendGrid send failed: %s", exc)
        return {"ok": False, "provider": "sendgrid", "error": str(exc)}


# ---------------------------------------------------------------------------
# Resend transport
# ---------------------------------------------------------------------------

def _send_resend(
    *,
    to: Union[str, List[str]],
    subject: str,
    body_html: str,
    body_text: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> Dict[str, Any]:
    api_key = _env("RESEND_API_KEY")
    if not api_key:
        return {"ok": False, "provider": "resend", "error": "RESEND_API_KEY not configured"}

    recipients = _normalize_recipients(to)
    payload: Dict[str, Any] = {
        "from": f"{_from_name()} <{_from_address()}>",
        "to": recipients,
        "subject": subject,
        "html": body_html,
    }
    if body_text:
        payload["text"] = body_text
    if reply_to:
        payload["reply_to"] = reply_to

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=15,
        )
        if resp.status_code >= 400:
            return {"ok": False, "provider": "resend", "error": resp.text[:512]}
        return {"ok": True, "provider": "resend", "delivered": True}
    except Exception as exc:
        logger.error("Resend send failed: %s", exc)
        return {"ok": False, "provider": "resend", "error": str(exc)}


# ---------------------------------------------------------------------------
# Postmark transport
# ---------------------------------------------------------------------------

def _send_postmark(
    *,
    to: Union[str, List[str]],
    subject: str,
    body_html: str,
    body_text: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> Dict[str, Any]:
    token = _env("POSTMARK_SERVER_TOKEN")
    if not token:
        return {"ok": False, "provider": "postmark", "error": "POSTMARK_SERVER_TOKEN not configured"}

    recipients = _normalize_recipients(to)
    payload: Dict[str, Any] = {
        "From": f"{_from_name()} <{_from_address()}>",
        "To": ", ".join(recipients),
        "Subject": subject,
        "HtmlBody": body_html,
    }
    if body_text:
        payload["TextBody"] = body_text
    if reply_to:
        payload["ReplyTo"] = reply_to

    try:
        resp = requests.post(
            "https://api.postmarkapp.com/email",
            json=payload,
            headers={
                "X-Postmark-Server-Token": token,
                "Accept": "application/json",
            },
            timeout=15,
        )
        if resp.status_code >= 400:
            return {"ok": False, "provider": "postmark", "error": resp.text[:512]}
        return {"ok": True, "provider": "postmark", "delivered": True}
    except Exception as exc:
        logger.error("Postmark send failed: %s", exc)
        return {"ok": False, "provider": "postmark", "error": str(exc)}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_PROVIDERS = {
    "smtp": _send_smtp,
    "sendgrid": _send_sendgrid,
    "resend": _send_resend,
    "postmark": _send_postmark,
}


def send_email(
    *,
    to: Union[str, List[str]],
    subject: str,
    body_html: str,
    body_text: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> Dict[str, Any]:
    """Send an email via the configured provider.

    Returns ``{"ok": bool, "provider": str, ...}``.
    Never raises; delivery failures are returned in the dict.
    """
    provider = _env("RELEASEGATE_EMAIL_PROVIDER").lower()
    send_fn = _PROVIDERS.get(provider)
    if send_fn is None:
        logger.info("Email (provider=%s) to=%s subject=%s", provider or "none", to, subject)
        return {"ok": True, "provider": "log", "delivered": False}

    result = send_fn(
        to=to,
        subject=subject,
        body_html=body_html,
        body_text=body_text,
        reply_to=reply_to,
    )
    logger.info(
        "Email sent via %s ok=%s to=%s subject=%s",
        result.get("provider"),
        result.get("ok"),
        to,
        subject,
    )
    return result
