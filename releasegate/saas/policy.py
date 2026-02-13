"""
Policy inheritance and configuration merging for multi-repo SaaS.
"""
from copy import deepcopy
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from releasegate.policy.inheritance import (
    deep_merge_policies,
    policy_resolution_hash,
    resolve_policy_inheritance,
)

SCOPE_KEY_ALIASES = {
    "project": "project_key",
    "workflow": "workflow_name",
    "transition": "transition_name",
}

CASE_INSENSITIVE_SCOPE_KEYS = {
    "environment",
    "project_key",
    "workflow_id",
    "workflow_name",
    "transition_id",
    "transition_name",
    "issue_type",
}


def merge_configs(org_config: Optional[Dict[str, Any]], repo_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deep merge two configuration dictionaries.
    Repository config overrides organization config.
    For nested dicts: merge recursively.
    For lists: repo replaces org (no merge).
    
    Args:
        org_config: Organization-level policy configuration
        repo_config: Repository-level policy overrides
        
    Returns:
        Merged configuration dictionary
    """
    return deep_merge_policies(org_config, repo_config)


def _canonical_scope_key(key: str) -> str:
    return SCOPE_KEY_ALIASES.get(key, key)


def _normalize_scope_dict(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    normalized: Dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        canonical = _canonical_scope_key(str(key))
        normalized[canonical] = value
    return normalized


def _normalize_for_compare(key: str, value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str) and key in CASE_INSENSITIVE_SCOPE_KEYS:
        return value.strip().lower()
    return value


def _scope_matches(selector: Dict[str, Any], context: Dict[str, Any]) -> bool:
    if not selector:
        return False
    for raw_key, expected in selector.items():
        key = _canonical_scope_key(str(raw_key))
        actual = context.get(key)
        if actual is None:
            return False

        if isinstance(expected, list):
            expected_values = [_normalize_for_compare(key, e) for e in expected]
            if _normalize_for_compare(key, actual) not in expected_values:
                return False
            continue

        if _normalize_for_compare(key, actual) != _normalize_for_compare(key, expected):
            return False
    return True


def resolve_scoped_policy(
    base_config: Optional[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Apply scope-based overlays from `policy_registry.scopes` using context matching.
    """
    resolved = deepcopy(base_config or {})
    if not context:
        return {
            "config": resolved,
            "matched_scope_ids": [],
            "matched_scope_count": 0,
        }

    registry = resolved.get("policy_registry")
    scopes = registry.get("scopes", []) if isinstance(registry, dict) else []
    if not isinstance(scopes, list):
        return {
            "config": resolved,
            "matched_scope_ids": [],
            "matched_scope_count": 0,
        }

    normalized_context = _normalize_scope_dict(context)
    matches: List[tuple[int, int, str, Dict[str, Any]]] = []
    for index, entry in enumerate(scopes):
        if not isinstance(entry, dict):
            continue
        selector = entry.get("match")
        if not isinstance(selector, dict):
            selector = entry.get("scope")
        selector = _normalize_scope_dict(selector if isinstance(selector, dict) else {})
        if not _scope_matches(selector, normalized_context):
            continue
        scope_id = str(entry.get("id") or f"scope-{index}")
        overlay = entry.get("config")
        if not isinstance(overlay, dict):
            overlay = {}
        matches.append((len(selector), index, scope_id, overlay))

    # Apply broad rules first, then narrower ones.
    matches.sort(key=lambda item: (item[0], item[1]))
    matched_scope_ids: List[str] = []
    for _, _, scope_id, overlay in matches:
        resolved = merge_configs(resolved, overlay)
        matched_scope_ids.append(scope_id)

    return {
        "config": resolved,
        "matched_scope_ids": matched_scope_ids,
        "matched_scope_count": len(matched_scope_ids),
    }


def resolve_effective_policy(
    session: Session,
    repo_id: int,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Resolve the effective policy for a repository by merging org and repo configs.
    
    Args:
        session: SQLAlchemy database session
        repo_id: Repository ID
        
    Returns:
        Dictionary containing:
        - config: Merged policy configuration
        - strictness: Enforcement level ("pass", "warn", "block")
        - org_id: Organization ID
        - repo_id: Repository ID
        - repo_name: Full repository name (owner/repo)
    """
    from releasegate.saas.db.models import Repository, Organization
    
    # Fetch repository
    repo = session.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise ValueError(f"Repository {repo_id} not found")
    
    # Fetch organization
    org = None
    if repo.org_id:
        org = session.query(Organization).filter(Organization.id == repo.org_id).first()
    
    normalized_context = _normalize_scope_dict(context or {})
    requested_env = str(normalized_context.get("environment") or "").strip()

    # Merge org/repo/environment layers.
    org_config = org.default_policy_config if org else {}
    repo_config = repo.policy_override or {}
    combined_for_env = merge_configs(org_config, repo_config)
    env_policies = combined_for_env.get("environment_policies") if isinstance(combined_for_env, dict) else {}
    inherited = resolve_policy_inheritance(
        org_policy=org_config,
        repo_policy=repo_config,
        environment=requested_env,
        environment_policies=env_policies if isinstance(env_policies, dict) else None,
    )
    scoped = resolve_scoped_policy(inherited["resolved_policy"], context=normalized_context)
    resolution_hash = policy_resolution_hash(scoped["config"])
    policy_scope = list(inherited["policy_scope"])
    if scoped["matched_scope_count"] > 0:
        policy_scope.append("scope")

    return {
        "config": scoped["config"],
        "strictness": repo.strictness_level or "block",
        "org_id": repo.org_id,
        "repo_id": repo.id,
        "repo_name": repo.full_name or repo.name,
        "policy_scope": policy_scope,
        "policy_resolution_hash": resolution_hash,
        "environment_scope": inherited["environment_scope"],
        "matched_scope_ids": scoped["matched_scope_ids"],
        "matched_scope_count": scoped["matched_scope_count"],
        "context": normalized_context,
    }
