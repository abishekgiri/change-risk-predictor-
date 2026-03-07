#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

from fastapi.testclient import TestClient


def _require_status(
    *,
    client: TestClient,
    method: str,
    path: str,
    headers: Dict[str, str],
    expected_status: int = 200,
) -> Dict[str, Any]:
    response = client.request(method, path, headers=headers)
    if response.status_code != expected_status:
        raise RuntimeError(
            f"{method} {path} returned {response.status_code} (expected {expected_status}): {response.text[:400]}"
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"{method} {path} returned non-object JSON payload")
    return payload


def main() -> int:
    os.environ.setdefault("RELEASEGATE_STORAGE_BACKEND", "sqlite")
    os.environ.setdefault("RELEASEGATE_INTERNAL_SERVICE_KEY", "phase0-smoke-key")
    os.environ.setdefault(
        "RELEASEGATE_INTERNAL_SERVICE_SCOPES",
        "policy:read,policy:write,tenant:read,tenant:write",
    )

    from releasegate.server import app

    tenant_id = os.getenv("DASHBOARD_TENANT_ID", "local")
    headers = {
        "X-Internal-Service-Key": os.environ["RELEASEGATE_INTERNAL_SERVICE_KEY"],
        "X-Tenant-Id": tenant_id,
    }
    checks: List[tuple[str, str]] = [
        ("GET", f"/dashboard/overview?tenant_id={tenant_id}&window_days=30&blocked_limit=25"),
        ("GET", f"/onboarding/status?tenant_id={tenant_id}"),
        ("GET", f"/onboarding/activation?tenant_id={tenant_id}"),
        ("GET", f"/dashboard/tenant/info?tenant_id={tenant_id}"),
    ]

    with TestClient(app) as client:
        for method, path in checks:
            _require_status(client=client, method=method, path=path, headers=headers)

    print("Phase 0 smoke checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - smoke command path
        print(f"Phase 0 smoke checks failed: {exc}", file=sys.stderr)
        raise
