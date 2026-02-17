from __future__ import annotations

from typing import Any, Dict, List

from releasegate.audit.reader import AuditReader
from releasegate.engine import ComplianceEngine
from releasegate.engine_core.policy_parser import compute_policy_hash
from releasegate.policy.loader import PolicyLoader
from releasegate.policy.policy_types import Policy
from releasegate.storage.base import resolve_tenant_id


def _normalized_status(overall_status: str) -> str:
    status = (overall_status or "").upper()
    if status == "BLOCK":
        return "BLOCKED"
    if status == "WARN":
        return "CONDITIONAL"
    return "ALLOWED"


def _normalize_raw_signals(raw: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(raw or {})
    normalized.setdefault("diff", {})
    normalized.setdefault("labels", [])
    normalized.setdefault("files_changed", [])
    normalized.setdefault("total_churn", 0)
    normalized.setdefault("commits", [])
    normalized.setdefault("critical_paths", [])
    normalized.setdefault("dependency_changes", [])
    normalized.setdefault("secrets_findings", [])
    normalized.setdefault("licenses", [])
    return normalized


def simulate_policy_impact(
    *,
    repo: str,
    limit: int = 100,
    policy_dir: str = "releasegate/policy/compiled",
    policy_base_dir: str | None = None,
    tenant_id: str | None = None,
) -> Dict[str, Any]:
    effective_tenant = resolve_tenant_id(tenant_id)
    loader = PolicyLoader(policy_dir=policy_dir, schema="compiled", strict=True, base_dir=policy_base_dir)
    loaded = loader.load_all()
    policies = [p for p in loaded if isinstance(p, Policy)]

    engine = ComplianceEngine({"tenant_id": effective_tenant, "policy_dir": policy_dir, "policy_base_dir": policy_base_dir})
    engine.policies = policies
    engine.policy_hash = compute_policy_hash(policies)

    rows = AuditReader.list_decisions(repo=repo, limit=limit, tenant_id=effective_tenant)
    records: List[Dict[str, Any]] = []
    original_counts: Dict[str, int] = {}
    simulated_counts: Dict[str, int] = {}

    simulated_rows = 0
    unsimulated_rows = 0
    changed_count = 0
    would_newly_block = 0
    would_unblock = 0

    for row in rows:
        full = row.get("full_decision_json")
        if isinstance(full, str):
            import json

            try:
                full = json.loads(full)
            except Exception:
                full = {}
        if not isinstance(full, dict):
            full = {}

        original_status = str(full.get("release_status") or row.get("release_status") or "UNKNOWN")
        original_counts[original_status] = original_counts.get(original_status, 0) + 1

        input_snapshot = full.get("input_snapshot") or {}
        raw_signals = input_snapshot.get("signal_map")

        if not isinstance(raw_signals, dict):
            unsimulated_rows += 1
            records.append(
                {
                    "decision_id": row.get("decision_id"),
                    "original_status": original_status,
                    "simulated_status": "UNSIMULATED",
                    "changed": False,
                    "reason": "missing input_snapshot.signal_map",
                }
            )
            continue

        run_result = engine.evaluate(_normalize_raw_signals(raw_signals))
        simulated_status = _normalized_status(run_result.overall_status)
        simulated_counts[simulated_status] = simulated_counts.get(simulated_status, 0) + 1
        simulated_rows += 1

        changed = simulated_status != original_status
        if changed:
            changed_count += 1
        if simulated_status == "BLOCKED" and original_status != "BLOCKED":
            would_newly_block += 1
        if original_status == "BLOCKED" and simulated_status != "BLOCKED":
            would_unblock += 1

        triggered_policies = [res.policy_id for res in run_result.results if res.triggered]
        records.append(
            {
                "decision_id": row.get("decision_id"),
                "original_status": original_status,
                "simulated_status": simulated_status,
                "changed": changed,
                "triggered_policies": triggered_policies,
            }
        )

    return {
        "tenant_id": effective_tenant,
        "repo": repo,
        "policy_dir": policy_dir,
        "policy_hash": engine.policy_hash,
        "policy_count": len(policies),
        "limit": limit,
        "total_rows": len(rows),
        "simulated_rows": simulated_rows,
        "unsimulated_rows": unsimulated_rows,
        "changed_count": changed_count,
        "would_newly_block": would_newly_block,
        "would_unblock": would_unblock,
        "original_counts": original_counts,
        "simulated_counts": simulated_counts,
        "records": records,
    }
