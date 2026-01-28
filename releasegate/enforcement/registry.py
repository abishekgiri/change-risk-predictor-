"""
Control Registry - orchestrates all Phase 3 controls.

Executes controls in deterministic order and aggregates signals.
"""
from typing import Dict, Any, List
from releasegate.enforcement.types import ControlContext, ControlSignalSet, ControlBase, Finding

# Import Phase 3 controls
from releasegate.enforcement.secrets import SecretsControl
from releasegate.enforcement.privileged_change import PrivilegedChangeControl
from releasegate.enforcement.approvals import ApprovalsControl
from releasegate.enforcement.licenses import LicensesControl
from releasegate.enforcement.env_boundary import EnvironmentBoundaryControl

class ControlRegistry:
    """
    Orchestrates all controls in deterministic order.
    
    Execution order:
    1. PrivilegedChangeControl
    2. SecretsControl
    3. ApprovalsControl
    4. LicensesControl
    5. EnvironmentBoundaryControl
    6. CoreRiskControl (existing Phase 2)
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.controls: List[ControlBase] = []
        self._register_default_controls()
    
    def _register_default_controls(self):
        """Register all default controls in deterministic order."""
        # Phase 3 controls (all 5 implemented)
        self.controls.append(PrivilegedChangeControl())
        self.controls.append(SecretsControl())
        self.controls.append(ApprovalsControl())
        self.controls.append(LicensesControl())
        self.controls.append(EnvironmentBoundaryControl())
    
    def register(self, control: ControlBase):
        """Register a custom control."""
        self.controls.append(control)
    
    def run_all(self, context: ControlContext) -> Dict[str, Any]:
        """
        Run all controls and aggregate signals.
        
        Args:
            context: Control execution context
        
        Returns:
            Dict with 'signals' and 'findings' keys
        """
        all_signals = {}
        all_findings: List[Finding] = []
        
        for control in self.controls:
            result = control.execute(context)
            all_signals.update(result.signals)
            all_findings.extend(result.findings)
        
        return {
            'signals': all_signals,
            'findings': all_findings
        }

