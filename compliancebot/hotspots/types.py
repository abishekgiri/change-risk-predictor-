from dataclasses import dataclass
from datetime import datetime
from typing import List

@dataclass
class FileRiskRecord:
    """
    File-level risk assessment record.
    Deterministic: same data → same risk score.
    """
    # Identity
    file_path: str
    
    # Final outputs
    risk_score: float # 0-1
    risk_bucket: str # HIGH | MEDIUM | LOW
    
    # Core signals
    incident_rate: float # Smoothed with Laplace
    churn_score: float # Normalized 0-1
    recent_churn: int # LOC changed in last N days
    samples: int # Total changes to this file
    incidents: int # Raw incident count
    
    # Context
    last_touched: datetime
    contributors: List[str] # Reason codes for explainability
    
    # Explainability
    explanation: List[str] # Human-readable bullets
