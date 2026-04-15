"""User signup, login, and session management.

Provides self-serve account creation that provisions a tenant, assigns the
owner role, and returns a JWT session token for immediate dashboard access.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt

from releasegate.saas.plans import normalize_plan_tier
from releasegate.saas.tenants import assign_tenant_role, create_tenant_profile
from releasegate.storage import get_storage_backend

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_PBKDF2_ITERATIONS = 310_000
_JWT_ALGORITHM = "HS256"
_SESSION_TTL_HOURS = 24


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _jwt_secret() -> str:
    secret = os.getenv("RELEASEGATE_JWT_SECRET", "").strip()
    if not secret:
        secret = os.getenv("RELEASEGATE_INTERNAL_SERVICE_KEY", "").strip()
    if not secret:
        raise RuntimeError("RELEASEGATE_JWT_SECRET must be configured for auth")
    return secret


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """Hash password with PBKDF2-SHA256.  Returns ``(hash_hex, salt_hex)``."""
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return dk.hex(), salt.hex()


def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        _PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(dk.hex(), hash_hex)


# ---------------------------------------------------------------------------
# Account creation
# ---------------------------------------------------------------------------

def create_user_account(
    *,
    email: str,
    password: str,
    org_name: str,
    plan: str = "starter",
) -> Dict[str, Any]:
    """Create a new user account + tenant atomically.

    Returns ``{"user_id", "tenant_id", "token", "roles", "redirect_url"}``.
    Raises ``ValueError`` on validation failures or duplicate email.
    """
    email = email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise ValueError("Invalid email address")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    org_name = org_name.strip()
    if not org_name:
        raise ValueError("Organization name is required")
    plan = normalize_plan_tier(plan)

    storage = get_storage_backend()
    existing = storage.fetchone(
        "SELECT user_id FROM user_accounts WHERE email = ?",
        (email,),
    )
    if existing:
        raise ValueError("An account with this email already exists")

    user_id = str(uuid.uuid4())
    tenant_id = f"org-{uuid.uuid4().hex[:12]}"
    password_hash, password_salt = hash_password(password)
    now = _utc_now().isoformat()

    storage.execute(
        """
        INSERT INTO user_accounts
            (user_id, email, password_hash, password_salt, tenant_id,
             display_name, created_at, updated_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (user_id, email, password_hash, password_salt, tenant_id, org_name, now, now),
    )

    create_tenant_profile(
        tenant_id=tenant_id,
        name=org_name,
        plan=plan,
        region="us-east",
        actor_id=user_id,
    )
    assign_tenant_role(
        tenant_id=tenant_id,
        actor_id=user_id,
        role="owner",
        assigned_by="system",
    )

    token = _generate_session_jwt(
        user_id=user_id,
        tenant_id=tenant_id,
        email=email,
        roles=["owner"],
    )

    return {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "token": token,
        "roles": ["owner"],
        "redirect_url": f"/onboarding?tenant_id={tenant_id}",
    }


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def authenticate_user(*, email: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate by email/password.  Returns user info or ``None``."""
    email = email.strip().lower()
    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT * FROM user_accounts WHERE email = ? AND is_active = 1",
        (email,),
    )
    if not row:
        return None
    if not verify_password(password, row["password_hash"], row["password_salt"]):
        return None

    storage.execute(
        "UPDATE user_accounts SET last_login_at = ? WHERE user_id = ?",
        (_utc_now().isoformat(), row["user_id"]),
    )

    roles = _get_user_roles(row["user_id"], row["tenant_id"])
    token = _generate_session_jwt(
        user_id=row["user_id"],
        tenant_id=row["tenant_id"],
        email=email,
        roles=roles,
    )
    return {
        "user_id": row["user_id"],
        "tenant_id": row["tenant_id"],
        "token": token,
        "roles": roles,
        "email": email,
    }


def get_user_profile(user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch user profile info."""
    storage = get_storage_backend()
    row = storage.fetchone(
        "SELECT user_id, email, tenant_id, display_name, created_at FROM user_accounts WHERE user_id = ? AND is_active = 1",
        (user_id,),
    )
    if not row:
        return None
    roles = _get_user_roles(row["user_id"], row["tenant_id"])
    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "tenant_id": row["tenant_id"],
        "display_name": row["display_name"],
        "roles": roles,
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _generate_session_jwt(
    *,
    user_id: str,
    tenant_id: str,
    email: str,
    roles: List[str],
) -> str:
    now = _utc_now()
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "email": email,
        "roles": roles,
        "iat": now,
        "exp": now + timedelta(hours=_SESSION_TTL_HOURS),
        "iss": "releasegate",
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=_JWT_ALGORITHM)


def _get_user_roles(user_id: str, tenant_id: str) -> List[str]:
    storage = get_storage_backend()
    rows = storage.fetchall(
        "SELECT role FROM tenant_role_assignments WHERE tenant_id = ? AND actor_id = ?",
        (tenant_id, user_id),
    )
    return [r["role"] for r in rows] if rows else ["viewer"]
