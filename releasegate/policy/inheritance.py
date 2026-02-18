from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Dict, Optional, Tuple

from releasegate.utils.canonical import sha256_json


def deep_merge_policies(base: Optional[Dict[str, Any]], override: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Legacy recursive merge kept for backwards compatibility.
    New policy resolution should use resolve_policy_inheritance() so we can track
    provenance and list merge strategies deterministically.
    """
    left = deepcopy(base or {})
    right = override or {}
    if not isinstance(left, dict):
        left = {}
    if not isinstance(right, dict):
        return left

    for key, value in right.items():
        if isinstance(left.get(key), dict) and isinstance(value, dict):
            left[key] = deep_merge_policies(left[key], value)
        else:
            left[key] = deepcopy(value)
    return left


def _canonical_scalar(value: Any) -> str:
    """Stable scalar key used for set membership/dedup."""
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _mark_provenance_tree(
    provenance: Dict[str, list[str]],
    value: Any,
    *,
    source: str,
    path: str = "",
) -> None:
    """
    Records a coarse but deterministic provenance map:
    - dict: recurse into children
    - everything else (including lists): treat as a leaf and mark the field path
    """
    if isinstance(value, dict):
        for k, v in value.items():
            key = str(k)
            child = f"{path}.{key}" if path else key
            _mark_provenance_tree(provenance, v, source=source, path=child)
        return
    provenance[path] = [source]


def _merge_with_provenance(  # noqa: C901
    base: Any,
    override: Any,
    *,
    source: str,
    provenance: Dict[str, list[str]],
    list_merge_strategies: Dict[str, str],
    path: str = "",
) -> Any:
    # Dict deep merge
    if isinstance(base, dict) and isinstance(override, dict):
        out = deepcopy(base)
        for k, v in override.items():
            key = str(k)
            child = f"{path}.{key}" if path else key
            if key in out:
                out[key] = _merge_with_provenance(
                    out[key],
                    v,
                    source=source,
                    provenance=provenance,
                    list_merge_strategies=list_merge_strategies,
                    path=child,
                )
            else:
                out[key] = deepcopy(v)
                _mark_provenance_tree(provenance, v, source=source, path=child)
        return out

    # List merge
    if isinstance(base, list) and isinstance(override, list):
        strategy = str(list_merge_strategies.get(path) or "replace").strip().lower()

        if strategy == "union":
            merged = list(base) + list(override)
            # Only union/dedup scalars deterministically; complex list merging is out of scope.
            if all(not isinstance(x, (dict, list)) for x in merged):
                seen: set[str] = set()
                unique: list[Any] = []
                for item in merged:
                    key = _canonical_scalar(item)
                    if key in seen:
                        continue
                    seen.add(key)
                    unique.append(item)

                # For pure string lists, sort for stability and readability.
                if all(isinstance(x, str) for x in unique):
                    unique = sorted(unique)  # type: ignore[assignment]

                existing_sources = set(provenance.get(path, []))
                existing_sources.add(source)
                provenance[path] = sorted(existing_sources)
                return unique

        # Default: replace
        provenance[path] = [source]
        return deepcopy(override)

    # Scalar / type mismatch: override wins
    _mark_provenance_tree(provenance, override, source=source, path=path)
    return deepcopy(override)


def select_environment_policy(
    environment_policies: Optional[Dict[str, Any]],
    environment: Optional[str],
) -> Tuple[Optional[str], Dict[str, Any]]:
    if not isinstance(environment_policies, dict):
        return None, {}
    env = str(environment or "").strip()
    if not env:
        return None, {}

    exact = environment_policies.get(env)
    if isinstance(exact, dict):
        return env, exact

    lowered = env.lower()
    for key, value in environment_policies.items():
        if str(key).strip().lower() == lowered and isinstance(value, dict):
            return str(key), value
    return None, {}


def policy_resolution_hash(resolved_policy: Dict[str, Any]) -> str:
    return sha256_json(resolved_policy or {})


def normalize_policy_defaults(policy: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    resolved = deepcopy(policy or {})
    dp = resolved.get("dependency_provenance")
    if not isinstance(dp, dict):
        dp = {}
    resolved["dependency_provenance"] = {
        "lockfile_required": bool(dp.get("lockfile_required", False)),
    }
    return resolved


def resolve_policy_inheritance(
    *,
    org_policy: Optional[Dict[str, Any]],
    repo_policy: Optional[Dict[str, Any]],
    environment: Optional[str],
    environment_policies: Optional[Dict[str, Any]] = None,
    list_merge_strategies: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    org_layer = org_policy if isinstance(org_policy, dict) else {}
    repo_layer = repo_policy if isinstance(repo_policy, dict) else {}
    env_key, env_layer = select_environment_policy(environment_policies, environment)

    strategies = {str(k): str(v) for k, v in (list_merge_strategies or {}).items() if k and v}

    provenance: Dict[str, list[str]] = {}
    resolved = deepcopy(org_layer)
    if org_layer:
        _mark_provenance_tree(provenance, org_layer, source="org")
    if repo_layer:
        resolved = _merge_with_provenance(
            resolved,
            repo_layer,
            source="repo",
            provenance=provenance,
            list_merge_strategies=strategies,
        )
    if env_layer:
        resolved = _merge_with_provenance(
            resolved,
            env_layer,
            source="environment",
            provenance=provenance,
            list_merge_strategies=strategies,
        )

    scope: list[str] = []
    if org_layer:
        scope.append("org")
    if repo_layer:
        scope.append("repo")
    if env_layer:
        scope.append("environment")

    resolved = normalize_policy_defaults(resolved)
    # Ensure default-injected fields have provenance.
    provenance.setdefault("dependency_provenance.lockfile_required", ["default"])

    return {
        "resolved_policy": resolved,
        "policy_scope": scope,
        "environment_scope": env_key,
        "policy_resolution_hash": policy_resolution_hash(resolved),
        "provenance": provenance,
        "list_merge_strategies": strategies,
    }

