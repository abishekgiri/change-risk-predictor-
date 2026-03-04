from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests


logger = logging.getLogger(__name__)
_ALERT_LOCK = threading.Lock()
_LAST_ALERT_AT: Dict[str, float] = {}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except Exception:
        return default


def _alert_key(*, tenant_id: str, title: str, body: str) -> str:
    material = f"{tenant_id}:{title}:{body}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _should_emit_alert(*, key: str, now_ts: float) -> bool:
    cooldown_seconds = _env_int("RELEASEGATE_ANCHOR_ALERT_COOLDOWN_SECONDS", 3600)
    with _ALERT_LOCK:
        previous = _LAST_ALERT_AT.get(key)
        if previous is not None and now_ts - previous < cooldown_seconds:
            return False
        _LAST_ALERT_AT[key] = now_ts
        return True


def send_anchor_alert(
    *,
    tenant_id: str,
    title: str,
    body: str,
    level: str = "warning",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    key = _alert_key(tenant_id=tenant_id, title=title, body=body)
    if not _should_emit_alert(key=key, now_ts=now.timestamp()):
        return {"ok": True, "suppressed": True}

    payload = {
        "component": "anchoring",
        "timestamp": now.isoformat(),
        "tenant_id": tenant_id,
        "title": title,
        "body": body,
        "metadata": metadata or {},
    }
    log_method = getattr(logger, level, logger.warning)
    log_method(json.dumps(payload, sort_keys=True, default=str))

    webhook = str(os.getenv("RELEASEGATE_ANCHOR_ALERT_WEBHOOK_URL") or "").strip()
    if not webhook:
        return {"ok": True, "delivered": False, "transport": "log"}
    timeout_seconds = max(1, _env_int("RELEASEGATE_ANCHOR_ALERT_TIMEOUT_SECONDS", 5))
    try:
        response = requests.post(
            webhook,
            json=payload,
            timeout=float(timeout_seconds),
        )
        if response.status_code >= 400:
            return {
                "ok": False,
                "delivered": False,
                "transport": "webhook",
                "status_code": response.status_code,
                "error": response.text[:512],
            }
    except Exception as exc:
        return {"ok": False, "delivered": False, "transport": "webhook", "error": str(exc)}
    return {"ok": True, "delivered": True, "transport": "webhook"}
