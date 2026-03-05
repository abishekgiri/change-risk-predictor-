from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from releasegate.anchoring.independent_checkpoints import create_independent_daily_checkpoint
from releasegate.storage.base import resolve_tenant_id
from releasegate.utils.canonical import canonical_json


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base_dir() -> Path:
    raw = str(os.getenv("RELEASEGATE_EXTERNAL_ANCHOR_BASE_DIR") or "audit_bundles/external_anchors").strip()
    return Path(raw)


def _immutable_dir() -> Path:
    raw = str(os.getenv("RELEASEGATE_EXTERNAL_ANCHOR_IMMUTABLE_DIR") or "").strip()
    if raw:
        return Path(raw)
    return _base_dir() / "object_lock"


def _git_mirror_dir() -> Path:
    raw = str(os.getenv("RELEASEGATE_EXTERNAL_ANCHOR_GIT_MIRROR_DIR") or "").strip()
    if raw:
        return Path(raw)
    return _base_dir() / "git_mirror"


def write_immutable_anchor_artifact(
    *,
    tenant_id: str,
    date_utc: str,
    checkpoint: Dict[str, Any],
) -> Dict[str, Any]:
    payload = checkpoint if isinstance(checkpoint, dict) else {}
    checkpoint_id = str(((payload.get("payload") or {}).get("checkpoint_id") or payload.get("checkpoint_id") or "").strip())
    if not checkpoint_id:
        raise ValueError("checkpoint_id is required in checkpoint payload")
    out_dir = _immutable_dir() / tenant_id / date_utc
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{checkpoint_id}.json"
    out_file.write_text(canonical_json(payload), encoding="utf-8")
    return {
        "destination": "immutable_object_store",
        "path": str(out_file),
        "checkpoint_id": checkpoint_id,
    }


def write_git_anchor_artifact(
    *,
    tenant_id: str,
    date_utc: str,
    checkpoint: Dict[str, Any],
) -> Dict[str, Any]:
    payload = checkpoint if isinstance(checkpoint, dict) else {}
    checkpoint_id = str(((payload.get("payload") or {}).get("checkpoint_id") or payload.get("checkpoint_id") or "").strip())
    checkpoint_hash = str(((payload.get("integrity") or {}).get("checkpoint_hash") or "").strip())
    ledger_root = str(((payload.get("payload") or {}).get("ledger_root") or "").strip())
    if not checkpoint_id:
        raise ValueError("checkpoint_id is required in checkpoint payload")

    tenant_dir = _git_mirror_dir() / tenant_id
    tenant_dir.mkdir(parents=True, exist_ok=True)
    log_file = tenant_dir / "anchors.jsonl"
    entry = {
        "written_at": _utc_now_iso(),
        "tenant_id": tenant_id,
        "date_utc": date_utc,
        "checkpoint_id": checkpoint_id,
        "checkpoint_hash": checkpoint_hash,
        "ledger_root": ledger_root,
    }
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(entry))
        handle.write("\n")
    return {
        "destination": "git_mirror",
        "path": str(log_file),
        "checkpoint_id": checkpoint_id,
    }


def publish_checkpoint_artifacts(
    *,
    tenant_id: Optional[str],
    date_utc: str,
    checkpoint: Dict[str, Any],
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    immutable = write_immutable_anchor_artifact(
        tenant_id=effective_tenant,
        date_utc=date_utc,
        checkpoint=checkpoint,
    )
    git_ref = write_git_anchor_artifact(
        tenant_id=effective_tenant,
        date_utc=date_utc,
        checkpoint=checkpoint,
    )
    return {
        "tenant_id": effective_tenant,
        "date_utc": date_utc,
        "immutable": immutable,
        "git_mirror": git_ref,
    }


def run_daily_anchor_checkpoint(
    *,
    tenant_id: Optional[str],
    date_utc: str,
    publish_anchor: bool = True,
    provider_name: Optional[str] = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    checkpoint = create_independent_daily_checkpoint(
        date_utc=date_utc,
        tenant_id=effective_tenant,
        publish_anchor=publish_anchor,
        provider_name=provider_name,
    )
    external_refs = publish_checkpoint_artifacts(
        tenant_id=effective_tenant,
        date_utc=date_utc,
        checkpoint=checkpoint,
    )
    return {
        "tenant_id": effective_tenant,
        "date_utc": date_utc,
        "checkpoint": checkpoint,
        "external_refs": external_refs,
    }
