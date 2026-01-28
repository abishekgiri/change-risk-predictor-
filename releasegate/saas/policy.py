"""
Policy inheritance and configuration merging for multi-repo SaaS.
"""
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session


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
    if not org_config:
        return repo_config or {}
    if not repo_config:
        return org_config or {}
    
    result = org_config.copy()
    
    for key, value in repo_config.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursive merge for nested dicts
            result[key] = merge_configs(result[key], value)
        else:
            # Direct override (including lists)
            result[key] = value
    
    return result


def resolve_effective_policy(session: Session, repo_id: int) -> Dict[str, Any]:
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
    from compliancebot.saas.db.models import Repository, Organization
    
    # Fetch repository
    repo = session.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise ValueError(f"Repository {repo_id} not found")
    
    # Fetch organization
    org = None
    if repo.org_id:
        org = session.query(Organization).filter(Organization.id == repo.org_id).first()
    
    # Merge configs
    org_config = org.default_policy_config if org else {}
    repo_config = repo.policy_override or {}
    merged_config = merge_configs(org_config, repo_config)
    
    return {
        "config": merged_config,
        "strictness": repo.strictness_level or "block",
        "org_id": repo.org_id,
        "repo_id": repo.id,
        "repo_name": repo.full_name or repo.name
    }
