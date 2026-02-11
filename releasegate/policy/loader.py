import os
import yaml
from typing import List, Union, Optional
from .types import PolicyDef
from .policy_types import Policy

class PolicyLoader:
    def __init__(self, policy_dir: Optional[str] = None, schema: str = "def", strict: bool = True):
        # schema: "def" (PolicyDef), "compiled" (Policy), or "auto"
        self.schema = schema
        self.strict = strict
        if policy_dir:
            self.policy_dir = policy_dir
        else:
            self.policy_dir = "releasegate/policy/compiled" if schema == "compiled" else "releasegate/policy/policies"

    def load_policies(self) -> List[Union[PolicyDef, Policy]]:
        """
        Recursively load all YAML policies from the directory.
        Returns validated PolicyDef objects sorted by Priority (asc), then ID.
        """
        policies = []
        
        if not os.path.exists(self.policy_dir):
            if self.strict:
                raise FileNotFoundError(f"Policy directory not found: {self.policy_dir}")
            return []

        for root, _, files in os.walk(self.policy_dir):
            for file in files:
                if file.startswith("_"):
                    continue
                if file.endswith(".yaml") or file.endswith(".yml"):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r") as f:
                            data = yaml.safe_load(f)
                            # Handle empty files
                            if not data:
                                continue
                            
                            # Support multi-document streams if needed, for now assume single
                            policy = self._parse_policy(data)
                            # Attach source_file only for PolicyDef (compiled Policy doesn't define it)
                            if isinstance(policy, PolicyDef):
                                policy.source_file = full_path
                            policies.append(policy)
                    except Exception as e:
                        if self.strict:
                            raise ValueError(f"Failed to load policy {full_path}: {e}") from e
                        import sys
                        print(f"WARN: Failed to load policy {full_path}: {e}", file=sys.stderr)
        
        # Sort deterministic
        if self.schema == "compiled" or (self.schema == "auto" and policies and isinstance(policies[0], Policy)):
            sorted_policies = sorted(policies, key=lambda p: p.policy_id)
            if self.strict and not sorted_policies:
                raise ValueError(f"No compiled policies loaded from {self.policy_dir}")
            return sorted_policies
        if self.strict and not policies:
            raise ValueError(f"No policies loaded from {self.policy_dir}")
        return sorted(policies, key=lambda p: (p.priority, p.id))

    def load_all(self) -> List[Union[PolicyDef, Policy]]:
        """Alias for load_policies (legacy compatibility)."""
        return self.load_policies()

    def _parse_policy(self, data: dict) -> Union[PolicyDef, Policy]:
        schema = self.schema
        if schema == "auto":
            if "controls" in data and "enforcement" in data:
                schema = "compiled"
            elif "when" in data and "then" in data:
                schema = "def"
            else:
                raise ValueError("Unknown policy schema (expected compiled or def fields)")

        if schema == "compiled":
            return Policy(**data)
        return PolicyDef(**data)
