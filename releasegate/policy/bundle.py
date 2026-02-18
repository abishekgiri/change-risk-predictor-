from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from releasegate.policy.inheritance import resolve_policy_inheritance
from releasegate.utils.json_schema import validate_json_schema_subset


SCHEMA_VERSION = "policy_bundle_v1"


@lru_cache(maxsize=1)
def _load_bundle_schema() -> Dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[2]
    schema_path = repo_root / "schemas" / "policy_bundle.schema.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


def build_policy_bundle(
    *,
    org_policy: Optional[Dict[str, Any]],
    repo_policy: Optional[Dict[str, Any]],
    environment: Optional[str],
    environment_policies: Optional[Dict[str, Any]] = None,
    list_merge_strategies: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    resolved = resolve_policy_inheritance(
        org_policy=org_policy,
        repo_policy=repo_policy,
        environment=environment,
        environment_policies=environment_policies,
        list_merge_strategies=list_merge_strategies,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "environment": str(environment).strip() if environment else None,
        "environment_scope": resolved.get("environment_scope"),
        "policy_scope": list(resolved.get("policy_scope") or []),
        "policy_resolution_hash": str(resolved.get("policy_resolution_hash") or ""),
        "resolved_policy": resolved.get("resolved_policy") or {},
        "provenance": resolved.get("provenance") or {},
        "list_merge_strategies": resolved.get("list_merge_strategies") or {},
    }


def validate_policy_bundle(bundle: Dict[str, Any]) -> List[str]:
    schema = _load_bundle_schema()
    return validate_json_schema_subset(bundle, schema)

