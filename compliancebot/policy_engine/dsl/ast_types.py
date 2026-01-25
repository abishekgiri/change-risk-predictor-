from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Union

@dataclass
class Expr:
    """Base class for all expressions."""
    pass

@dataclass
class BinaryExpr(Expr):
    """Expression with left/right operands and logical operator (AND, OR)."""
    left: Expr
    operator: str
    right: Expr

@dataclass
class CompareExpr(Expr):
    """Comparison expression (e.g., secrets.severity == 'HIGH')."""
    left: str # Signal name (e.g., "secrets.severity")
    operator: str # ==, !=, >, >=, <, <=, in, not in
    right: Any # Literal value (str, int, bool, list)

@dataclass
class EnforcementNode:
    """Enforcement action (BLOCK, WARN, COMPLIANT)."""
    result: str
    message: Optional[str] = None

@dataclass
class RuleNode:
    """A single compliance rule (when condition -> enforce action)."""
    condition: Expr
    enforcement: EnforcementNode

@dataclass
class ControlNode:
    """Definition of a control's inputs and evidence."""
    name: str
    signals: List[str]
    evidence: List[str]

@dataclass
class PolicyNode:
    """Root node for a DSL policy."""
    policy_id: str
    version: str
    name: str
    description: Optional[str]
    controls: List[ControlNode]
    rules: List[RuleNode]
    compliance: Dict[str, str] # Standard -> Clause mapping
    effective_date: Optional[str] = None
    supersedes: Optional[str] = None

