import os
from typing import Dict, Any, List, Tuple
from releasegate.policy.policy_types import Policy
from releasegate.policy.loader import PolicyLoader
from releasegate.enforcement.core_risk import CoreRiskControl
from releasegate.enforcement.registry import ControlRegistry
from releasegate.enforcement.types import ControlContext
from releasegate.observability.internal_metrics import incr
from releasegate.storage.base import resolve_tenant_id
from releasegate.utils.ttl_cache import TTLCache, yaml_tree_fingerprint
from releasegate.engine_core import (
    ComplianceRunResult,
    PolicyResult,
    check_condition as check_signal_condition,
    compute_policy_hash,
    evaluate_policy,
    flatten_signals,
)


def _policy_cache_ttl_seconds() -> float:
    try:
        return float(os.getenv("RELEASEGATE_POLICY_REGISTRY_CACHE_TTL_SECONDS", "300"))
    except Exception:
        return 300.0


_POLICY_CACHE = TTLCache(
    max_entries=max(1, int(os.getenv("RELEASEGATE_POLICY_REGISTRY_CACHE_MAX_ENTRIES", "256"))),
    default_ttl_seconds=max(1.0, _policy_cache_ttl_seconds()),
)

class ComplianceEngine:
    """
    Deterministic Policy Evaluation Engine.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.policy_dir = str(config.get("policy_dir") or "releasegate/policy/compiled")
        self.tenant_id = resolve_tenant_id(config.get("tenant_id"), allow_none=True) or "system"
        self.loader = PolicyLoader(policy_dir=self.policy_dir, schema="compiled")
        self.policies = self._load_compiled_policies()
        self.policy_hash = self._compute_policy_hash(self.policies)
        
        # Instantiate Controls
        self.core_risk = CoreRiskControl(config)
        
        # Phase 3: Control Registry (all 5 controls)
        self.control_registry = ControlRegistry(config)

    def _policy_cache_key(self) -> Tuple[str, str, str]:
        return (
            self.tenant_id,
            os.path.abspath(self.policy_dir),
            yaml_tree_fingerprint(self.policy_dir),
        )

    def _load_compiled_policies(self) -> List[Policy]:
        cache_key = self._policy_cache_key()
        hit, cached = _POLICY_CACHE.get(cache_key)
        if hit:
            incr("cache_policy_registry_hit", tenant_id=self.tenant_id)
            return list(cached)

        incr("cache_policy_registry_miss", tenant_id=self.tenant_id)
        loaded = self.loader.load_all()
        policies = [policy for policy in loaded if isinstance(policy, Policy)]
        _POLICY_CACHE.set(cache_key, tuple(policies), ttl_seconds=_policy_cache_ttl_seconds())
        return policies

    def evaluate(self, raw_signals: Dict[str, Any]) -> ComplianceRunResult:
        # 1. Gather Control Signals from Core Risk (Phase 2)
        core_output = self.core_risk.evaluate(raw_signals)
        
        # 2. Run Phase 3 Controls (if diff provided)
        phase3_signals = {}
        phase3_findings = []
        
        if "diff" in raw_signals:
            # Create control context for Phase 3 controls
            context = ControlContext(
                repo=raw_signals.get("repo", "unknown"),
                pr_number=raw_signals.get("pr_number", 0),
                diff=raw_signals.get("diff") or {},
                config=self.config,
                provider=raw_signals.get("provider")
            )
            
            # Run all Phase 3 controls
            registry_result = self.control_registry.run_all(context)
            phase3_signals = registry_result.get("signals", {})
            phase3_findings = registry_result.get("findings", [])
        
        # 3. Flatten Signals (combine Phase 2 + Phase 3)
        signal_map = self._flatten_signals({
            "core_risk": core_output,
            "features": core_output.get("signals", {}), 
            "raw": raw_signals,
            **phase3_signals # Add Phase 3 signals
        })
        
        policy_results = []
        overall_status = "COMPLIANT"
        
        # 4. Evaluate Each Policy
        for policy in self.policies:
            p_res = self._evaluate_policy(policy, signal_map)
            policy_results.append(p_res)
            
            if p_res.status == "BLOCK":
                overall_status = "BLOCK"
            elif p_res.status == "WARN" and overall_status != "BLOCK":
                overall_status = "WARN"
        
        # 5. Check for Overrides (Phase 2 Step 8)
        # Check raw signals for override labels
        labels = raw_signals.get("labels", [])
        override_labels = ["compliance-override", "emergency", "hotfix-approved"]
        
        found_override = [l for l in labels if l in override_labels]
        
        metadata = {
            "core_risk_score": core_output.get("violation_severity"),
            "core_risk_level": core_output.get("severity_level"),
            "raw_features": core_output.get("raw_features", {}),
            "policy_hash": self.policy_hash,
            "policy_count": len(self.policies),
            "phase3_signals": phase3_signals,
            "phase3_findings_count": len(phase3_findings),
            "phase3_findings": [
                {
                    "control_id": f.control_id,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "file_path": f.file_path
                }
                for f in phase3_findings
            ]
        }
        
        if found_override:
            # Apply Override
            metadata["override"] = {
                "active": True,
                "reason": f"Label present: {found_override[0]}",
                "original_status": overall_status,
                "approver": "label_holder" # MVP
            }
            # Force Compliance
            overall_status = "COMPLIANT"
        
        return ComplianceRunResult(
            overall_status=overall_status,
            results=policy_results,
            metadata=metadata
        )

    def _compute_policy_hash(self, policies: List[Policy]) -> str:
        return compute_policy_hash(policies)

    def _evaluate_policy(self, policy: Policy, signals: Dict[str, Any]) -> PolicyResult:
        return evaluate_policy(
            policy,
            signals,
            check_condition=self._check_condition,
        )

    def _check_condition(self, actual, operator, expected) -> bool:
        return check_signal_condition(actual, operator, expected)

    def _flatten_signals(self, data: Dict[str, Any], prefix="") -> Dict[str, Any]:
        return flatten_signals(data, prefix=prefix, preserve_keys={"files_changed"})
