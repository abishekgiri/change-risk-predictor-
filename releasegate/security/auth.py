from __future__ import annotations

import hashlib
import hmac
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence

import jwt
from fastapi import Depends, HTTPException, Request

from releasegate.security.api_keys import authenticate_api_key
from releasegate.security.audit import log_security_event
from releasegate.security.rate_limit import enforce_ip_rate_limit, enforce_tenant_rate_limit
from releasegate.security.types import AuthContext
from releasegate.security.webhook_keys import lookup_active_webhook_key
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


_WEBHOOK_PATH_PATTERNS = (
    re.compile(r"^/webhooks/"),
    re.compile(r"^/integrations/[^/]+/webhook(?:$|/)"),
    re.compile(r"^/(jira|github|gitlab)/webhook(?:$|/)"),
)


def _split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _normalize_strings(value: object) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        if "," in raw:
            return _split_csv(raw)
        return [raw]
    if isinstance(value, Sequence):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _auth_error(status_code: int, error_code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "error_code": error_code,
            "message": message,
        },
    )


def _is_webhook_route(path: str) -> bool:
    normalized = str(path or "").strip() or "/"
    for pattern in _WEBHOOK_PATH_PATTERNS:
        if pattern.match(normalized):
            return True
    return False


def _present_auth_methods(request: Request) -> List[str]:
    methods: List[str] = []
    authz = request.headers.get("Authorization", "")
    if authz.lower().startswith("bearer "):
        methods.append("jwt")
    if (request.headers.get("X-API-Key") or "").strip():
        methods.append("api_key")
    signature_headers = (
        "X-Signature",
        "X-Key-Id",
        "X-Timestamp",
        "X-Nonce",
    )
    if any((request.headers.get(name) or "").strip() for name in signature_headers):
        methods.append("signature")
    return methods


def _request_ip(request: Request) -> str:
    trust_proxy = (os.getenv("RELEASEGATE_TRUST_PROXY_HEADERS", "false").strip().lower() in {"1", "true", "yes", "on"})
    if trust_proxy:
        forwarded = (request.headers.get("X-Forwarded-For") or "").strip()
        if forwarded:
            return forwarded.split(",", 1)[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


def _safe_log_security_event(
    request: Request,
    *,
    action: str,
    auth_method: str = "none",
    tenant_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    try:
        effective_tenant = resolve_tenant_id(tenant_id, allow_none=True) or "unknown"
        principal = f"ip:{_request_ip(request)}"
        log_security_event(
            tenant_id=effective_tenant,
            principal_id=principal,
            auth_method=auth_method,
            action=action,
            target_type="path",
            target_id=request.url.path,
            metadata=metadata or {},
        )
    except Exception:
        return


def _decode_jwt_token(token: str) -> AuthContext:
    secret = (os.getenv("RELEASEGATE_JWT_SECRET") or "").strip()
    if not secret:
        raise _auth_error(401, "AUTH_JWT_UNAVAILABLE", "JWT auth is not configured")

    algorithm = (os.getenv("RELEASEGATE_JWT_ALGORITHM", "HS256") or "HS256").strip()
    issuer = (os.getenv("RELEASEGATE_JWT_ISSUER", "releasegate") or "releasegate").strip()
    audience = (os.getenv("RELEASEGATE_JWT_AUDIENCE", "releasegate-api") or "releasegate-api").strip()

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
            options={
                "require": ["exp", "iss", "sub", "tenant_id", "aud"],
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise _auth_error(401, "AUTH_JWT_EXPIRED", "JWT token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise _auth_error(401, "AUTH_JWT_INVALID", "JWT token is invalid") from exc

    tenant = payload.get("tenant_id")
    principal = payload.get("sub")
    if not tenant or not principal:
        raise _auth_error(401, "AUTH_JWT_CLAIMS", "JWT token missing required tenant_id/sub claims")

    if payload.get("iat") is not None:
        try:
            issued_at = datetime.fromtimestamp(float(payload["iat"]), tz=timezone.utc)
        except Exception as exc:
            raise _auth_error(401, "AUTH_JWT_IAT", "JWT token has invalid iat claim") from exc
        max_future = int(os.getenv("RELEASEGATE_JWT_MAX_FUTURE_IAT_SECONDS", "60"))
        if issued_at > datetime.now(timezone.utc) + timedelta(seconds=max_future):
            raise _auth_error(401, "AUTH_JWT_IAT_FUTURE", "JWT token iat is in the future")

    roles = _normalize_strings(payload.get("roles")) or ["read_only"]
    scopes = _normalize_strings(payload.get("scopes"))
    return AuthContext(
        tenant_id=resolve_tenant_id(str(tenant)),
        principal_id=str(principal),
        auth_method="jwt",
        roles=sorted(set(roles)),
        scopes=sorted(set(scopes)),
    )


def _parse_signature_timestamp(raw: str) -> datetime:
    value = (raw or "").strip()
    if not value:
        raise _auth_error(401, "AUTH_SIGNATURE_TIMESTAMP", "Missing X-Timestamp header")
    if value.isdigit():
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise _auth_error(401, "AUTH_SIGNATURE_TIMESTAMP", "Invalid X-Timestamp format") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


async def _read_request_body_limited(request: Request, *, max_bytes: int) -> bytes:
    cached = getattr(request.state, "_releasegate_body_cache", None)
    if cached is not None:
        return cached
    preloaded = getattr(request, "_body", None)
    if preloaded is not None:
        if len(preloaded) > max_bytes:
            raise _auth_error(
                413,
                "REQUEST_TOO_LARGE",
                f"Request exceeds max size ({max_bytes} bytes)",
            )
        request.state._releasegate_body_cache = preloaded
        return preloaded

    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise _auth_error(
                    413,
                    "REQUEST_TOO_LARGE",
                    f"Request exceeds max size ({max_bytes} bytes)",
                )
        except ValueError as exc:
            raise _auth_error(400, "REQUEST_CONTENT_LENGTH_INVALID", "Invalid Content-Length header") from exc

    size = 0
    chunks: List[bytes] = []
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise _auth_error(
                413,
                "REQUEST_TOO_LARGE",
                f"Request exceeds max size ({max_bytes} bytes)",
            )
        chunks.append(chunk)
    body = b"".join(chunks)
    request.state._releasegate_body_cache = body
    request._body = body  # allow endpoint handlers to call request.body() safely
    return body


def _canonical_signature_payload(
    *,
    timestamp_raw: str,
    nonce: str,
    method: str,
    path: str,
    body: bytes,
) -> bytes:
    parts = [
        (timestamp_raw or "").strip().encode("utf-8"),
        nonce.encode("utf-8"),
        (method or "POST").upper().encode("utf-8"),
        (path or "/").encode("utf-8"),
        body,
    ]
    return b"\n".join(parts)


def _consume_nonce(
    *,
    tenant_id: str,
    integration_id: str,
    key_id: str,
    nonce: str,
    signature: str,
    skew_seconds: int,
) -> None:
    init_db()
    storage = get_storage_backend()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=max(skew_seconds, 60))
    storage.execute(
        "DELETE FROM webhook_nonces WHERE expires_at <= ?",
        (now.isoformat(),),
    )
    try:
        storage.execute(
            """
            INSERT INTO webhook_nonces (
                tenant_id, integration_id, key_id, nonce, signature_hash, used_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                integration_id,
                key_id,
                nonce,
                hashlib.sha256(signature.encode("utf-8")).hexdigest(),
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )
    except Exception as exc:
        raise _auth_error(401, "AUTH_SIGNATURE_REPLAY", "Webhook signature replay detected") from exc


async def _authenticate_signature(request: Request, *, rate_profile: str) -> Optional[AuthContext]:
    signature = (request.headers.get("X-Signature") or "").strip()
    if not signature:
        return None

    key_id = (request.headers.get("X-Key-Id") or "").strip()
    if not key_id:
        raise _auth_error(401, "AUTH_SIGNATURE_KEY_ID", "Missing X-Key-Id header")

    key_record = lookup_active_webhook_key(key_id)
    if not key_record:
        raise _auth_error(401, "AUTH_SIGNATURE_KEY_UNKNOWN", "Unknown webhook signing key")

    tenant_id = resolve_tenant_id(str(key_record["tenant_id"]))
    integration_id = str(key_record["integration_id"])
    secret = str(key_record["secret"])

    # Enforce tenant-level webhook limit before body parsing and nonce writes.
    enforce_tenant_rate_limit(tenant_id=tenant_id, profile=rate_profile)
    request.state.pre_tenant_rate_limited = True

    timestamp_raw = request.headers.get("X-Timestamp")
    nonce = (request.headers.get("X-Nonce") or "").strip()
    if not nonce:
        raise _auth_error(401, "AUTH_SIGNATURE_NONCE", "Missing X-Nonce header")

    signed_at = _parse_signature_timestamp(str(timestamp_raw))
    skew_seconds = int(os.getenv("RELEASEGATE_SIGNATURE_MAX_SKEW_SECONDS", "300"))
    now = datetime.now(timezone.utc)
    if abs((now - signed_at).total_seconds()) > skew_seconds:
        raise _auth_error(401, "AUTH_SIGNATURE_STALE", "Webhook signature timestamp outside allowed skew")

    max_request_bytes = int(os.getenv("RELEASEGATE_MAX_REQUEST_BYTES", "1048576"))
    body = await _read_request_body_limited(request, max_bytes=max_request_bytes)
    canonical = _canonical_signature_payload(
        timestamp_raw=str(timestamp_raw),
        nonce=nonce,
        method=request.method,
        path=request.url.path,
        body=body,
    )
    expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    provided = signature
    if provided.startswith("sha256="):
        provided = provided.split("=", 1)[1]
    if not hmac.compare_digest(expected, provided):
        raise _auth_error(401, "AUTH_SIGNATURE_INVALID", "Webhook signature mismatch")

    _consume_nonce(
        tenant_id=tenant_id,
        integration_id=integration_id,
        key_id=key_id,
        nonce=nonce,
        signature=signature,
        skew_seconds=skew_seconds,
    )

    roles = _split_csv(os.getenv("RELEASEGATE_SIGNATURE_DEFAULT_ROLES", "operator")) or ["operator"]
    scopes = _split_csv(os.getenv("RELEASEGATE_SIGNATURE_DEFAULT_SCOPES", "enforcement:write"))
    return AuthContext(
        tenant_id=tenant_id,
        principal_id=f"webhook:{integration_id}:{key_id}",
        auth_method="signature",
        roles=sorted(set(roles)),
        scopes=sorted(set(scopes)),
        key_id=key_id,
        integration_id=integration_id,
    )


async def authenticate_request(
    request: Request,
    *,
    allow_signature: bool = False,
    rate_profile: str = "default",
) -> AuthContext:
    methods = _present_auth_methods(request)
    signature_route = allow_signature or _is_webhook_route(request.url.path)

    if len(methods) > 1:
        _safe_log_security_event(
            request,
            action="auth.mixed_methods_rejected",
            metadata={"methods": methods},
        )
        raise _auth_error(401, "AUTH_MIXED_METHODS", "Only one authentication method is allowed per request")

    if signature_route:
        if methods != ["signature"]:
            _safe_log_security_event(
                request,
                action="auth.webhook_non_signature_rejected",
                metadata={"methods": methods},
            )
            raise _auth_error(401, "AUTH_SIGNATURE_REQUIRED", "Webhook endpoints require signature authentication")
        context = await _authenticate_signature(request, rate_profile=rate_profile)
        if context is None:
            raise _auth_error(401, "AUTH_SIGNATURE_REQUIRED", "Webhook endpoints require signature authentication")
        return context

    if "signature" in methods:
        _safe_log_security_event(
            request,
            action="auth.signature_not_allowed",
            metadata={"methods": methods},
        )
        raise _auth_error(401, "AUTH_SIGNATURE_FORBIDDEN", "Signature authentication is only allowed on webhook routes")

    if methods == ["api_key"]:
        api_key_raw = (request.headers.get("X-API-Key") or "").strip()
        key_record = authenticate_api_key(api_key_raw)
        if not key_record:
            raise _auth_error(401, "AUTH_API_KEY_INVALID", "API key is invalid")
        return AuthContext(
            tenant_id=resolve_tenant_id(key_record["tenant_id"]),
            principal_id=f"api_key:{key_record['key_id']}",
            auth_method="api_key",
            roles=sorted(set(_normalize_strings(key_record.get("roles")) or ["read_only"])),
            scopes=sorted(set(_normalize_strings(key_record.get("scopes")))),
            key_id=str(key_record["key_id"]),
        )

    if methods == ["jwt"]:
        authz = request.headers.get("Authorization", "")
        token = authz.split(" ", 1)[1].strip() if " " in authz else ""
        if not token:
            raise _auth_error(401, "AUTH_BEARER_MISSING", "Missing bearer token")
        return _decode_jwt_token(token)

    raise _auth_error(401, "AUTH_REQUIRED", "Authentication is required")


def _has_scope(auth: AuthContext, required_scope: str) -> bool:
    if "admin" in auth.roles:
        return True
    scopes = set(auth.scopes)
    return "*" in scopes or required_scope in scopes


def _authorize(auth: AuthContext, *, roles: Iterable[str], scopes: Iterable[str]) -> None:
    role_set = set(auth.roles)
    required_roles = {str(role) for role in roles}
    if required_roles and not role_set.intersection(required_roles):
        raise _auth_error(403, "RBAC_FORBIDDEN", "Role does not allow this action")
    for scope in scopes:
        if not _has_scope(auth, str(scope)):
            raise _auth_error(403, "RBAC_SCOPE_FORBIDDEN", f"Missing required scope: {scope}")


def require_access(
    *,
    roles: Optional[Iterable[str]] = None,
    scopes: Optional[Iterable[str]] = None,
    allow_signature: bool = False,
    rate_profile: str = "default",
):
    async def _dependency(request: Request) -> AuthContext:
        ip = _request_ip(request)
        enforce_ip_rate_limit(ip=ip, profile=rate_profile)

        max_request_bytes = int(os.getenv("RELEASEGATE_MAX_REQUEST_BYTES", "1048576"))
        signature_route = allow_signature or _is_webhook_route(request.url.path)
        if not signature_route:
            await _read_request_body_limited(request, max_bytes=max_request_bytes)

        auth = await authenticate_request(
            request,
            allow_signature=allow_signature,
            rate_profile=rate_profile,
        )
        _authorize(auth, roles=roles or [], scopes=scopes or [])

        if not getattr(request.state, "pre_tenant_rate_limited", False):
            enforce_tenant_rate_limit(tenant_id=auth.tenant_id, profile=rate_profile)

        request.state.auth_context = auth
        return auth

    return Depends(_dependency)


def tenant_from_request(auth: AuthContext, requested_tenant: Optional[str]) -> str:
    if not requested_tenant:
        return auth.tenant_id
    resolved = resolve_tenant_id(requested_tenant)
    if resolved != auth.tenant_id and "admin" not in auth.roles:
        raise _auth_error(403, "TENANT_SCOPE_FORBIDDEN", "Cannot access another tenant")
    return resolved
