from typing import Dict, Any, List, Optional
from compliancebot.policies.types import Policy, ControlSignal
from compliancebot.policies.loader import PolicyLoader
from compliancebot.controls.core_risk import CoreRiskControl
from compliancebot.controls.registry import ControlRegistry
from compliancebot.controls.types import ControlContext
from pydantic import BaseModel

class PolicyResult(BaseModel):
    policy_id: str
    name: str
    status: str # COMPLIANCE / WARN / BLOCK
    triggered: bool
    violations: List[str]
    evidence: Dict[str, Any]
    traceability: Optional[Dict[str, Any]] = None # Injected metadata

class ComplianceRunResult(BaseModel):
    overall_status: str # COMPLIANCE / WARN / BLOCK
    results: List[PolicyResult]
    metadata: Dict[str, Any]

class ComplianceEngine:
    """
    Deterministic Policy Evaluation Engine.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.loader = PolicyLoader("compliancebot/policies/compiled")
        self.policies = self.loader.load_all()
        
        # Instantiate Controls
        self.core_risk = CoreRiskControl(config)
        
        # Phase 3: Control Registry (all 5 controls)
        self.control_registry = ControlRegistry(config)

    def evaluate(self, raw_signals: Dict[str, Any]) -> ComplianceRunResult:
        # 1. Gather Control Signals from Core Risk (Phase 2)
        core_output = self.core_risk.evaluate(raw_signals)
        
        # 2. Run Phase 3 Controls (if diff provided)
        phase3_signals = {}
        phase3_findings = []
        
        if "diff" in raw_signals and raw_signals["diff"]:
            # Create control context for Phase 3 controls
            context = ControlContext(
                repo=raw_signals.get("repo", "unknown"),
                pr_number=raw_signals.get("pr_number", 0),
                diff=raw_signals.get("diff", {}),
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

    def _evaluate_policy(self, policy: Policy, signals: Dict[str, Any]) -> PolicyResult:
        violations = []
        triggered = False
        
        # AND Logic: All controls in a policy are evaluated
        # If ANY control matches the trigger condition, the policy triggers? 
        # Typically policies specify "violations".
        # Let's assume: If ALL conditions match, then enforcement triggers?
        # WAIT. "High Severity Changes Require Review". Signal: severity >= HIGH.
        # This implies "Trigger if severity is HIGH".
        # What if multiple signals? usually AND logic for the trigger.
        
        triggers = []
        for ctrl in policy.controls:
            actual_val = signals.get(ctrl.signal)
            if self._check_condition(actual_val, ctrl.operator, ctrl.value):
                triggers.append(f"{ctrl.signal} ({actual_val}) {ctrl.operator} {ctrl.value}")
        
        # Policy is "violated" (triggered) if ALL control conditions are met? 
        # Or ANY? 
        # For SEC-PR-004: "High Risk" AND "Churn > 500".
        # Yes, usually composite trigger.
        
        if len(triggers) == len(policy.controls):
            triggered = True
            violations = triggers
            status = policy.enforcement.result # BLOCK or WARN
        else:
            status = "COMPLIANT"
        
        return PolicyResult(
            policy_id=policy.policy_id,
            name=policy.name,
            status=status,
            triggered=triggered,
            violations=violations,
            evidence={}, # Todo: extract specific evidence
            traceability=policy.metadata or {}
        )

    def _check_condition(self, actual, operator, expected) -> bool:
        if actual is None: return False
        try:
            if operator == "==": return actual == expected
            if operator == "!=": return actual != expected
            if operator == ">": return float(actual) > float(expected)
            if operator == ">=": return float(actual) >= float(expected)
            if operator == "<": return float(actual) < float(expected)
            if operator == "<=": return float(actual) <= float(expected)
            if operator == "in": return actual in expected
            if operator == "not in": return actual not in expected
        except:
            return False
        return False

    def _flatten_signals(self, data: Dict[str, Any], prefix="") -> Dict[str, Any]:
        """Recursive flatten for dot notation."""
        out = {}
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict) and k != "files_changed": # Don't flatten lists of files
                out.update(self._flatten_signals(v, key))
            else:
                out[key] = v
        return out
