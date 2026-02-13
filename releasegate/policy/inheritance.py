from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Optional, Tuple

from releasegate.utils.canonical import sha256_json


def deep_merge_policies(base: Optional[Dict[str, Any]], override: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recursively merge policy dictionaries.
    Lower level overrides higher level values.
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


def resolve_policy_inheritance(
    *,
    org_policy: Optional[Dict[str, Any]],
    repo_policy: Optional[Dict[str, Any]],
    environment: Optional[str],
    environment_policies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    org_layer = org_policy if isinstance(org_policy, dict) else {}
    repo_layer = repo_policy if isinstance(repo_policy, dict) else {}
    env_key, env_layer = select_environment_policy(environment_policies, environment)

    resolved = deep_merge_policies(org_layer, repo_layer)
    resolved = deep_merge_policies(resolved, env_layer)

    scope: list[str] = []
    if org_layer:
        scope.append("org")
    if repo_layer:
        scope.append("repo")
    if env_layer:
        scope.append("environment")

    return {
        "resolved_policy": resolved,
        "policy_scope": scope,
        "environment_scope": env_key,
        "policy_resolution_hash": policy_resolution_hash(resolved),
    }
