from typing import List, Dict, Any, Optional
import os
import json
import hashlib
from compliancebot.audit.types import TraceableFinding
from compliancebot.engine import PolicyResult

# Assuming Phase 4 compiled policies are in a known location
COMPILED_ROOT = "compliancebot/policies/compiled"

class TraceabilityInjector:
    """
    Enriches raw Engine results with Traceable metadata from Phase 4 compiled artifacts.
    """
    
    def __init__(self, compiled_root: str = COMPILED_ROOT):
        self.compiled_root = compiled_root
        self.policy_cache = {}
    
    def _load_policy(self, policy_id: str) -> Optional[Dict]:
        """Loads compiled YAML for a rule ID."""
        if policy_id in self.policy_cache:
            return self.policy_cache[policy_id]
        
        # Try to find file (Phase 4 compilation naming convention: POLICY_ID.yaml)
        # Note: Rule IDs are unique files in Phase 4 output
        path = os.path.join(self.compiled_root, f"{policy_id}.yaml")
        if not os.path.exists(path):
            # Try searching subdirs (e.g. standards/soc2/) 
            for root, _, files in os.walk(self.compiled_root):
                if f"{policy_id}.yaml" in files:
                    path = os.path.join(root, f"{policy_id}.yaml")
                    break
            else:
                return None
        
        try:
            with open(path) as f:
                data = json.load(f) # It's JSON-compatible YAML (loaded as dict)
                self.policy_cache[policy_id] = data
                return data
        except Exception:
            return None

    def inject(self, result: PolicyResult) -> TraceableFinding:
        """
        Converts a raw Engine PolicyResult into a TraceableFinding.
        """
        # Load compiled policy metadata
        # PolicyResult.policy_id is the compiled rule ID (e.g. SEC-PR-002.R1)
        policy_data = self._load_policy(result.policy_id) or {}
        
        meta = policy_data.get("metadata", {})
        
        # Calculate stable fingerprint
        # Hash(policy_id + context) - context is roughly the violations list
        fingerprint_input = f"{result.policy_id}:{str(result.violations)}"
        fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()
        
        return TraceableFinding(
            finding_id=f"evt_{fingerprint[:12]}",
            fingerprint=fingerprint,
            message=str(result.violations), # Summary of violations
            severity="HIGH" if result.status == "BLOCK" else "MEDIUM", # simplified
            
            # Traceability
            policy_id=result.policy_id,
            parent_policy=meta.get("parent_policy", "UNKNOWN"),
            rule_id=result.policy_id.split(".")[-1] if "." in result.policy_id else "UNKNOWN",
            policy_version=meta.get("version", "0.0.0"),
            
            # Compliance
            compliance=meta.get("compliance", {}),
            
            # Source
            dsl_source=meta.get("source_file", None),
            compiled_source=f"{result.policy_id}.yaml"
        )

