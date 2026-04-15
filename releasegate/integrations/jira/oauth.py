"""Atlassian OAuth 2.0 (3LO) integration for per-tenant Jira connections.

Environment variables:
    JIRA_OAUTH_CLIENT_ID      : Atlassian app client ID
    JIRA_OAUTH_CLIENT_SECRET  : Atlassian app client secret
    JIRA_OAUTH_REDIRECT_URI   : Callback URL
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

from releasegate.storage import get_storage_backend

logger = logging.getLogger(__name__)

_ATLASSIAN_AUTH_URL = "https://auth.atlassian.com/authorize"
_ATLASSIAN_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
_ATLASSIAN_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"
_SCOPES = "read:jira-work read:jira-user write:jira-work offline_access"


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def is_oauth_configured() -> bool:
    """Return True if Jira OAuth env vars are set."""
    return bool(_env("JIRA_OAUTH_CLIENT_ID")) and bool(_env("JIRA_OAUTH_CLIENT_SECRET"))


def generate_authorize_url(tenant_id: str) -> str:
    """Build the Atlassian authorization URL.

    The *state* parameter encodes the tenant_id with a random nonce for CSRF
    protection.  The callback handler verifies the state to retrieve the
    originating tenant.
    """
    client_id = _env("JIRA_OAUTH_CLIENT_ID")
    redirect_uri = _env("JIRA_OAUTH_REDIRECT_URI")
    if not client_id or not redirect_uri:
        raise RuntimeError("JIRA_OAUTH_CLIENT_ID and JIRA_OAUTH_REDIRECT_URI must be set")

    nonce = secrets.token_urlsafe(16)
    state = _encode_state(tenant_id, nonce)
    _store_oauth_state(tenant_id, nonce)

    params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": _SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
        "response_type": "code",
        "prompt": "consent",
    }
    qs = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
    return f"{_ATLASSIAN_AUTH_URL}?{qs}"


def exchange_code_for_tokens(code: str) -> Dict[str, Any]:
    """Exchange an authorization code for access + refresh tokens."""
    resp = requests.post(
        _ATLASSIAN_TOKEN_URL,
        json={
            "grant_type": "authorization_code",
            "client_id": _env("JIRA_OAUTH_CLIENT_ID"),
            "client_secret": _env("JIRA_OAUTH_CLIENT_SECRET"),
            "code": code,
            "redirect_uri": _env("JIRA_OAUTH_REDIRECT_URI"),
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def refresh_access_token(refresh_token: str) -> Dict[str, Any]:
    """Refresh an expired access token."""
    resp = requests.post(
        _ATLASSIAN_TOKEN_URL,
        json={
            "grant_type": "refresh_token",
            "client_id": _env("JIRA_OAUTH_CLIENT_ID"),
            "client_secret": _env("JIRA_OAUTH_CLIENT_SECRET"),
            "refresh_token": refresh_token,
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_accessible_resources(access_token: str) -> List[Dict[str, Any]]:
    """Fetch Jira Cloud sites the token can access."""
    resp = requests.get(
        _ATLASSIAN_RESOURCES_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Credential storage
# ---------------------------------------------------------------------------

def store_jira_credentials(
    *,
    tenant_id: str,
    cloud_id: str,
    site_url: str,
    access_token: str,
    refresh_token: str,
    expires_in: int,
) -> None:
    """Persist OAuth tokens for a tenant."""
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=max(expires_in, 60))).isoformat()
    storage = get_storage_backend()
    storage.execute(
        """
        INSERT INTO tenant_jira_credentials
            (tenant_id, cloud_id, site_url, access_token, refresh_token,
             token_expires_at, scopes, connected_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id) DO UPDATE SET
            cloud_id = excluded.cloud_id,
            site_url = excluded.site_url,
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            token_expires_at = excluded.token_expires_at,
            scopes = excluded.scopes,
            updated_at = excluded.updated_at
        """,
        (tenant_id, cloud_id, site_url, access_token, refresh_token,
         expires_at, _SCOPES, now.isoformat(), now.isoformat()),
    )


def get_jira_credentials(tenant_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve stored credentials, auto-refreshing if the token has expired."""
    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT * FROM tenant_jira_credentials WHERE tenant_id = ?",
        (tenant_id,),
    )
    if not row:
        return None

    creds = dict(row)
    expires_at = datetime.fromisoformat(creds["token_expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) >= expires_at - timedelta(minutes=2):
        try:
            tokens = refresh_access_token(creds["refresh_token"])
            store_jira_credentials(
                tenant_id=tenant_id,
                cloud_id=creds["cloud_id"],
                site_url=creds["site_url"],
                access_token=tokens["access_token"],
                refresh_token=tokens.get("refresh_token", creds["refresh_token"]),
                expires_in=tokens.get("expires_in", 3600),
            )
            creds["access_token"] = tokens["access_token"]
        except Exception:
            logger.warning("Failed to refresh Jira token for tenant %s", tenant_id)
    return creds


def get_jira_connection_status(tenant_id: str) -> Dict[str, Any]:
    """Return connection status without exposing tokens."""
    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT site_url, connected_at FROM tenant_jira_credentials WHERE tenant_id = ?",
        (tenant_id,),
    )
    if not row:
        return {"connected": False, "site_url": None, "connected_at": None}
    return {
        "connected": True,
        "site_url": row["site_url"],
        "connected_at": row["connected_at"],
    }


def revoke_jira_credentials(tenant_id: str) -> None:
    """Delete stored Jira credentials for a tenant."""
    storage = get_storage_backend()
    storage.execute(
        "DELETE FROM tenant_jira_credentials WHERE tenant_id = ?",
        (tenant_id,),
    )


# ---------------------------------------------------------------------------
# State helpers (CSRF protection)
# ---------------------------------------------------------------------------

def _encode_state(tenant_id: str, nonce: str) -> str:
    material = json.dumps({"t": tenant_id, "n": nonce}, separators=(",", ":"), sort_keys=True)
    sig = hashlib.sha256(f"{material}:{_env('JIRA_OAUTH_CLIENT_SECRET')}".encode()).hexdigest()[:16]
    import base64
    return base64.urlsafe_b64encode(f"{material}|{sig}".encode()).decode()


def decode_state(state: str) -> Optional[str]:
    """Decode and verify the state param, returning the tenant_id or None."""
    import base64
    try:
        raw = base64.urlsafe_b64decode(state.encode()).decode()
        material, sig = raw.rsplit("|", 1)
        expected = hashlib.sha256(f"{material}:{_env('JIRA_OAUTH_CLIENT_SECRET')}".encode()).hexdigest()[:16]
        if sig != expected:
            return None
        data = json.loads(material)
        return data.get("t")
    except Exception:
        return None


def _store_oauth_state(tenant_id: str, nonce: str) -> None:
    """Store nonce for optional replay detection."""
    storage = get_storage_backend()
    try:
        storage.execute(
            """
            INSERT INTO tenant_jira_credentials
                (tenant_id, cloud_id, site_url, access_token, refresh_token,
                 token_expires_at, scopes, connected_at, updated_at)
            VALUES (?, '', '', '', '', '', '', ?, ?)
            ON CONFLICT(tenant_id) DO NOTHING
            """,
            (tenant_id, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
    except Exception:
        pass
