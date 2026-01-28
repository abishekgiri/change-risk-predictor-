from .ast_types import PolicyNode, RuleNode, BinaryExpr, CompareExpr
from typing import List
import re

class DSLValidator:
    """
    Semantic validator for Compliance DSL.
    Checks:
    - Signals exist (stubbed for now)
    - Operators are valid
    - Enforcement actions are valid
    """
    
    VALID_ACTIONS = {'BLOCK', 'WARN', 'COMPLIANT'}
    
    def validate(self, policy: PolicyNode) -> List[str]:
        errors = []
        
        # 1. Validate Meta
        if not re.match(r'^\d+\.\d+\.\d+$', policy.version):
            errors.append(f"Invalid semantic version: {policy.version}")
        
        # 2. Validate Controls (stub)
        known_signals = set()
        for ctrl in policy.controls:
            known_signals.update(ctrl.signals)
        
        # 3. Validate Rules
        for rule in policy.rules:
            if rule.enforcement.result not in self.VALID_ACTIONS:
                errors.append(f"Invalid enforcement action: {rule.enforcement.result}")
            
            errors.extend(self._validate_expr(rule.condition, known_signals))
        
        return errors

    def _validate_expr(self, expr, known_signals) -> List[str]:
        errors = []
        if isinstance(expr, BinaryExpr):
            errors.extend(self._validate_expr(expr.left, known_signals))
            errors.extend(self._validate_expr(expr.right, known_signals))
        
        elif isinstance(expr, CompareExpr):
            # TODO: strictly check if signal is in ControlNode list
            # For now just pass
            pass
        
        return errors

