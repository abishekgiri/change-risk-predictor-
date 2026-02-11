from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class PolicyResult(BaseModel):
    policy_id: str
    name: str
    status: str  # COMPLIANT / WARN / BLOCK
    triggered: bool
    violations: List[str]
    evidence: Dict[str, Any]
    traceability: Optional[Dict[str, Any]] = None


class ComplianceRunResult(BaseModel):
    overall_status: str  # COMPLIANT / WARN / BLOCK
    results: List[PolicyResult]
    metadata: Dict[str, Any]
