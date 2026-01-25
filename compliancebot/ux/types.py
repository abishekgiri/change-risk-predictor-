from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ExplanationFactor:
    """
    A single human-readable reason for a risk decision.
    """
    label: str # "High code churn"
    evidence: str # "File changed 14 times in 30 days"
    severity: float # 0.0 - 1.0 rank
    remediation: List[str] # ["Split PR", "Add tests"]

@dataclass
class DecisionExplanation:
    """
    Structured explanation object.
    """
    summary: str # "Deployment blocked due to high change risk"
    factors: List[ExplanationFactor]
    narrative: str # Full paragraph text

@dataclass
class DecisionRecord:
    """
    Immutable Enterprise Decision Object.
    Configured for auditability and replay.
    """
    decision_id: str
    timestamp: str # ISO 8601
    repo: str
    pr_number: int
    
    # Outcomes
    decision: str # BLOCK | WARN | PASS
    risk_score: int # 0-100
    risk_level: str # HIGH | MEDIUM | LOW
    
    # Traceability
    policy_id: str # Rule that made the call
    
    # UX Layer
    explanation: DecisionExplanation
    
    # Raw Inputs (Snapshot)
    features: Dict[str, Any]
    
    def to_dict(self):
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "repo": self.repo,
            "pr_number": self.pr_number,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "policy_id": self.policy_id,
            "explanation": {
                "summary": self.explanation.summary,
                "factors": [f.__dict__ for f in self.explanation.factors],
                "narrative": self.explanation.narrative
            },
            "features": self.features
        }

def validate_features(features: Dict[str, Any], mode: str = "standard") -> bool:
    """
    Ensures critical feature keys exist to prevent scoring/explainer mismatch.
    """
    required_keys = [
        "total_churn", # Explainer expects this
        "files_changed", # Scoring often uses this
        "risky_files", # For Hotspot detection
        "dependency_change" # For Dept check
    ]
    
    missing = [k for k in required_keys if k not in features]
    if missing:
        # In a strict system we'd raise error, for now we log/return False
        # print(f"Warning: Missing feature keys: {missing}")
        return False
    return True

