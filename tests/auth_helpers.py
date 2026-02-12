from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

import jwt


def jwt_headers(
    *,
    tenant_id: str = "tenant-test",
    principal_id: str = "test-user",
    roles: Optional[Iterable[str]] = None,
    scopes: Optional[Iterable[str]] = None,
) -> dict[str, str]:
    token = jwt.encode(
        {
            "sub": principal_id,
            "tenant_id": tenant_id,
            "roles": list(roles or ["admin"]),
            "scopes": list(
                scopes
                or [
                    "policy:read",
                    "policy:write",
                    "override:write",
                    "proofpack:read",
                    "checkpoint:read",
                    "enforcement:write",
                ]
            ),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iss": os.getenv("RELEASEGATE_JWT_ISSUER", "releasegate"),
            "aud": os.getenv("RELEASEGATE_JWT_AUDIENCE", "releasegate-api"),
        },
        os.getenv("RELEASEGATE_JWT_SECRET", "test-jwt-secret"),
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}
