import yaml
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union
from .types import EvaluationContext, Actor, Change, Timing

class ContextBuilder:
    """
    Hydrates the EvaluationContext from various sources with safe defaults.
    """

    def __init__(self, config_path: str = "releasegate/config.yaml"):
        self._actor: Optional[Actor] = None
        self._change: Optional[Change] = None
        
        self.config = self._load_config(config_path)
        
        # Defaults
        self._environment: str = "UNKNOWN"
        self._window_status: str = "OPEN"
        self._now_fn = lambda: datetime.now(timezone.utc)

    def _load_config(self, path: str) -> Dict[str, Any]:
        """Load configuration for role mapping etc."""
        if os.path.exists(path):
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        return {}

    def with_actor(self, 
                   user_id: str, 
                   login: str, 
                   role: Optional[str] = None, 
                   team: str = "Unknown") -> 'ContextBuilder':
        
        # Role Resolution: Explicit -> Config Map -> Default -> "Engineer"
        if not role:
            role_map = self.config.get("actors", {}).get("github_to_role", {})
            role = role_map.get(login)
            
        if not role:
             role = self.config.get("actors", {}).get("default_role", "Engineer")

        self._actor = Actor(
            user_id=user_id, 
            login=login,
            role=role, 
            team=team
        )
        return self

    def with_change(self, 
                   repo: str, 
                   change_id: str, 
                   files: List[str], 
                   change_type: str = "PR",
                   lines_changed: int = 0,
                   # Enriched fields
                   base_branch: Optional[str] = None,
                   head_sha: Optional[str] = None,
                   author_login: Optional[str] = None,
                   labels: List[str] = None,
                   is_draft: bool = False,
                   title: Optional[str] = None) -> 'ContextBuilder':
        
        self._change = Change(
            repository=repo,
            change_id=change_id,
            files=files,
            lines_changed=lines_changed,
            change_type=change_type,
            title=title,
            base_branch=base_branch,
            head_sha=head_sha,
            author_login=author_login,
            labels=labels or [],
            is_draft=is_draft
        )
        return self

    def with_environment(self, env: str) -> 'ContextBuilder':
        if env:
            self._environment = env
        return self
    
    def check_change_window(self) -> 'ContextBuilder':
        # Placeholder for real Change Window logic
        # In a real impl, this would check self._now_fn() against a calendar
        self._window_status = "OPEN"
        return self

    def build(self) -> EvaluationContext:
        if not self._actor:
            # Try to infer actor from change author if available
            if self._change and self._change.author_login:
                 self.with_actor(
                     user_id=self._change.author_login,
                     login=self._change.author_login
                 )
            
        if not self._actor:
            raise ValueError("Actor is required for Context")
        
        if not self._change:
            raise ValueError("Change is required for Context")

        timing = Timing(
            timestamp=self._now_fn(),
            change_window=self._window_status
        )

        return EvaluationContext(
            context_id=str(uuid.uuid4()),
            actor=self._actor,
            change=self._change,
            environment=self._environment,
            timing=timing
        )

    # Helper for testing to inject time
    def _set_time_provider(self, fn):
        self._now_fn = fn
        return self
