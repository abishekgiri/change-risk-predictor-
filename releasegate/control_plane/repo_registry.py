from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from releasegate.utils.paths import safe_join_under


class RepoRegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    owners: List[str] = Field(default_factory=list)
    enforcement_mode: Literal["monitor", "enforce"] = "monitor"
    environment: Optional[str] = None

    # Policy sources (layered inheritance inputs)
    org_policy_path: Optional[str] = None
    repo_policy_path: Optional[str] = None
    environment_policies_path: Optional[str] = None
    list_merge_strategies: Dict[str, str] = Field(default_factory=dict)

    @field_validator("repo")
    @classmethod
    def _strip_repo(cls, value: str) -> str:
        cleaned = str(value or "").strip()
        if not cleaned:
            raise ValueError("repo must be non-empty")
        return cleaned


class RepoRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    repos: List[RepoRegistryEntry] = Field(default_factory=list)

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        if int(value) != 1:
            raise ValueError("supported repo registry version is 1")
        return int(value)


def load_repo_registry(path: str = "repos.yaml", *, base_dir: Optional[str | Path] = None) -> RepoRegistry:
    registry_path = safe_join_under(base_dir or Path.cwd(), path)
    raw = registry_path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("repos.yaml must contain a top-level object")
    try:
        return RepoRegistry.model_validate(data)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def get_repo_entry(
    *,
    registry: RepoRegistry,
    repo: str,
) -> Optional[RepoRegistryEntry]:
    target = str(repo or "").strip()
    if not target:
        return None
    for entry in registry.repos:
        if entry.repo == target:
            return entry
    return None


def load_repo_policy_inputs(
    *,
    entry: RepoRegistryEntry,
    base_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Load policy layer inputs for a repo from registry paths.
    Returned dict matches the analyze-pr config "policy_inheritance" shape.
    """
    base = base_dir or Path.cwd()

    def _load_obj(path: Optional[str]) -> dict:
        if not path:
            return {}
        p = safe_join_under(base, path)
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"expected object in {path}")
        return loaded

    org_policy = _load_obj(entry.org_policy_path)
    repo_policy = _load_obj(entry.repo_policy_path)
    env_policies = _load_obj(entry.environment_policies_path) if entry.environment_policies_path else {}
    if env_policies and not isinstance(env_policies, dict):
        raise ValueError("environment_policies must be an object mapping env -> policy object")

    return {
        **({"environment": entry.environment} if entry.environment else {}),
        "enforcement": {"mode": entry.enforcement_mode},
        "policy_inheritance": {
            "org_policy": org_policy,
            "repo_policies": {entry.repo: repo_policy} if repo_policy else {},
            "environment_policies": env_policies or {},
            "list_merge_strategies": entry.list_merge_strategies or {},
        },
    }
