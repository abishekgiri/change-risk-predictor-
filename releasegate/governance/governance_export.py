from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, BinaryIO, Dict, Iterable, List, Optional, Tuple

from releasegate.governance.integrity import get_tenant_governance_integrity
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db


_PAGE_SIZE = 1000


@dataclass
class GovernanceExportArtifact:
    tenant_id: str
    archive_path: str
    archive_name: str
    temp_dir: str
    manifest: Dict[str, Any]


def _utc(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


def _range_for_export(export_type: str, year: int, quarter: Optional[int]) -> Tuple[datetime, datetime, str]:
    normalized_type = str(export_type or "").strip().lower()
    if normalized_type not in {"quarter", "annual"}:
        raise ValueError("type must be 'quarter' or 'annual'")
    if year < 2000 or year > 9999:
        raise ValueError("year must be a four-digit year")

    if normalized_type == "annual":
        start = _utc(year, 1, 1)
        end = _utc(year + 1, 1, 1)
        label = f"{year}"
        return start, end, label

    if quarter is None:
        raise ValueError("quarter is required when type=quarter")
    q = int(quarter)
    if q not in {1, 2, 3, 4}:
        raise ValueError("quarter must be 1, 2, 3, or 4")

    start_month = ((q - 1) * 3) + 1
    start = _utc(year, start_month, 1)
    if q == 4:
        end = _utc(year + 1, 1, 1)
    else:
        end = _utc(year, start_month + 3, 1)
    label = f"{year}_Q{q}"
    return start, end, label


def _parse_json_column(row: Dict[str, Any], key: str) -> None:
    value = row.get(key)
    if isinstance(value, (dict, list)):
        return
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return
        try:
            parsed = json.loads(raw)
        except Exception:
            return
        if isinstance(parsed, (dict, list)):
            row[key] = parsed


def _iter_paged_rows(query: str, params: Iterable[Any]) -> Iterable[Dict[str, Any]]:
    storage = get_storage_backend()
    offset = 0
    while True:
        rows = storage.fetchall(
            f"{query} LIMIT ? OFFSET ?",
            [*list(params), _PAGE_SIZE, offset],
        )
        if not rows:
            break
        for row in rows:
            yield dict(row)
        if len(rows) < _PAGE_SIZE:
            break
        offset += len(rows)


def _write_ndjson(
    *,
    handle: BinaryIO,
    rows: Iterable[Dict[str, Any]],
    json_columns: Optional[List[str]] = None,
) -> Dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    size = 0
    for row in rows:
        if json_columns:
            for column in json_columns:
                _parse_json_column(row, column)
        line = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        handle.write(line)
        digest.update(line)
        count += 1
        size += len(line)
    return {
        "count": count,
        "sha256": digest.hexdigest(),
        "size": size,
    }


def cleanup_export_artifact(temp_dir: str) -> None:
    if not temp_dir:
        return
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except OSError:
        pass


def build_governance_export(
    *,
    tenant_id: str,
    export_type: str,
    year: int,
    quarter: Optional[int],
) -> GovernanceExportArtifact:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)

    start, end, label = _range_for_export(export_type, int(year), quarter)
    range_start = start.isoformat()
    range_end = end.isoformat()

    temp_dir = tempfile.mkdtemp(prefix="releasegate-governance-export-")

    dataset_specs = [
        {
            "filename": "decisions.ndjson",
            "query": """
                SELECT *
                FROM audit_decisions
                WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
                ORDER BY created_at ASC, decision_id ASC
            """,
            "params": [effective_tenant, range_start, range_end],
            "json_columns": ["full_decision_json"],
        },
        {
            "filename": "policies.ndjson",
            "query": """
                SELECT *
                FROM policy_registry_entries
                WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
                ORDER BY created_at ASC, policy_id ASC, version ASC
            """,
            "params": [effective_tenant, range_start, range_end],
            "json_columns": ["policy_json", "lint_errors_json", "lint_warnings_json"],
        },
        {
            "filename": "approvals.ndjson",
            "query": """
                SELECT *
                FROM decision_approvals
                WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
                ORDER BY created_at ASC, approval_id ASC
            """,
            "params": [effective_tenant, range_start, range_end],
            "json_columns": ["approval_scope_json", "justification_json"],
        },
        {
            "filename": "overrides.ndjson",
            "query": """
                SELECT *
                FROM audit_overrides
                WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
                ORDER BY created_at ASC, override_id ASC
            """,
            "params": [effective_tenant, range_start, range_end],
            "json_columns": [],
        },
        {
            "filename": "signals.ndjson",
            "query": """
                SELECT *
                FROM signal_attestations
                WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
                ORDER BY created_at ASC, signal_id ASC
            """,
            "params": [effective_tenant, range_start, range_end],
            "json_columns": ["payload_json"],
        },
        {
            "filename": "deployments.ndjson",
            "query": """
                SELECT *
                FROM deployment_decision_links
                WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
                ORDER BY created_at ASC, deployment_event_id ASC
            """,
            "params": [effective_tenant, range_start, range_end],
            "json_columns": ["violation_codes_json"],
        },
        {
            "filename": "anchors.ndjson",
            "query": """
                SELECT *
                FROM audit_independent_daily_checkpoints
                WHERE tenant_id = ? AND created_at >= ? AND created_at < ?
                ORDER BY created_at ASC, checkpoint_id ASC
            """,
            "params": [effective_tenant, range_start, range_end],
            "json_columns": ["anchor_receipt_json"],
        },
    ]

    file_metadata: Dict[str, Dict[str, Any]] = {}
    for spec in dataset_specs:
        file_path = os.path.join(temp_dir, spec["filename"])
        with open(file_path, "wb") as handle:
            stats = _write_ndjson(
                handle=handle,
                rows=_iter_paged_rows(spec["query"], spec["params"]),
                json_columns=spec.get("json_columns") or [],
            )
        file_metadata[spec["filename"]] = stats

    integrity_summary = get_tenant_governance_integrity(
        tenant_id=effective_tenant,
        window_days=90,
    )
    integrity_summary["export_range"] = {
        "start": range_start,
        "end_exclusive": range_end,
    }
    integrity_summary_path = os.path.join(temp_dir, "integrity_summary.json")
    with open(integrity_summary_path, "w", encoding="utf-8") as handle:
        json.dump(integrity_summary, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with open(integrity_summary_path, "rb") as handle:
        payload = handle.read()
    file_metadata["integrity_summary.json"] = {
        "count": 1,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }

    instructions = (
        "1) Verify each file hash in manifest.json using SHA-256.\n"
        "2) Validate NDJSON lines are parseable JSON objects.\n"
        "3) Recompute policy/decision integrity checks using recorded hashes where needed.\n"
        "4) Keep this archive immutable once delivered for audit evidence retention.\n"
    )
    instructions_path = os.path.join(temp_dir, "verification_instructions.txt")
    with open(instructions_path, "w", encoding="utf-8") as handle:
        handle.write(instructions)
    file_metadata["verification_instructions.txt"] = {
        "count": 1,
        "sha256": hashlib.sha256(instructions.encode("utf-8")).hexdigest(),
        "size": len(instructions.encode("utf-8")),
    }

    manifest = {
        "export_version": "phase17_v1",
        "tenant_id": effective_tenant,
        "type": str(export_type).lower(),
        "year": int(year),
        "quarter": int(quarter) if quarter is not None else None,
        "range_start": range_start,
        "range_end_exclusive": range_end,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "record_counts": {
            name: int(meta.get("count") or 0)
            for name, meta in sorted(file_metadata.items())
        },
        "file_hashes": {
            name: str(meta.get("sha256") or "")
            for name, meta in sorted(file_metadata.items())
        },
        "file_sizes": {
            name: int(meta.get("size") or 0)
            for name, meta in sorted(file_metadata.items())
        },
    }
    manifest_path = os.path.join(temp_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    archive_name = f"governance_export_{label}.zip"
    archive_path = os.path.join(temp_dir, archive_name)
    with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(manifest_path, arcname="manifest.json")
        for filename in sorted(file_metadata.keys()):
            bundle.write(os.path.join(temp_dir, filename), arcname=filename)

    return GovernanceExportArtifact(
        tenant_id=effective_tenant,
        archive_path=archive_path,
        archive_name=archive_name,
        temp_dir=temp_dir,
        manifest=manifest,
    )
