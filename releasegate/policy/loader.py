import os
import yaml
from typing import List
from .types import PolicyDef

class PolicyLoader:
    def __init__(self, policy_dir: str = "releasegate/policy/policies"):
        self.policy_dir = policy_dir

    def load_policies(self) -> List[PolicyDef]:
        """
        Recursively load all YAML policies from the directory.
        Returns validated PolicyDef objects sorted by Priority (asc), then ID.
        """
        policies = []
        
        if not os.path.exists(self.policy_dir):
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
                            policy = PolicyDef(**data)
                            policy.source_file = full_path
                            policies.append(policy)
                    except Exception as e:
                        import sys
                        print(f"WARN: Failed to load policy {full_path}: {e}", file=sys.stderr)
        
        # Sort deterministic: Priority ASC (1 wins over 100), then ID ASC
        return sorted(policies, key=lambda p: (p.priority, p.id))

    def load_all(self) -> List[PolicyDef]:
        """Alias for load_policies (legacy compatibility)."""
        return self.load_policies()
