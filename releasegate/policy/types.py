from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class CompiledPolicy:
    """
    Represents a single compiled YAML policy file.
    In Phase 4 1-to-many architecture, one DSL Policy produces multiple CompiledPolicies.
    """
    filename: str # e.g., "SEC-PR-002.R1.yaml"
    content: Dict[str, Any] # Complete YAML content including metadata
    source_hash: str # Hash of the source DSL file
    policy_id: str # The unique ID (SEC-PR-002.R1)

