import os
import yaml
from typing import List, Dict
from compliancebot.policies.types import Policy

class PolicyLoader:
    """
    Loads and validates policies from YAML files.
    """
    def __init__(self, policy_dir: str):
        self.policy_dir = policy_dir

    def load_all(self) -> List[Policy]:
        """Load all enabled policies from the directory."""
        policies = []
        if not os.path.exists(self.policy_dir):
            print(f"Warning: Policy directory {self.policy_dir} does not exist.")
            return []

        for root, _, files in os.walk(self.policy_dir):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    p = self._load_file(os.path.join(root, file))
                    if p and p.enabled:
                        policies.append(p)
        return policies

    def _load_file(self, path: str) -> Policy:
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            
            # Allow list of policies in one file or single policy per file
            # For now, assume single policy per file for simplicity
            return Policy(**data)
        except Exception as e:
            print(f"Error loading policy from {path}: {e}")
            return None

