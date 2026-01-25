from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

@dataclass
class AuditEvent:
    """
    Immutable, append-only record of a compliance check run.
    """
    audit_id: str
    timestamp: str # ISO 8601
    actor: str
    repo: str
    pr_number: int
    head_sha: str
    
    overall_status: str # PASS / BLOCK / WARN
    risk_score: int
    
    # Hashes for integrity
    bundle_manifest_hash: str # SHA256 of the evidence bundle manifest
    previous_event_hash: Optional[str] # Chain link
    event_hash: Optional[str] = None # Self hash (computed last)

    def to_dict(self):
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "repo": self.repo,
            "pr_number": self.pr_number,
            "head_sha": self.head_sha,
            "overall_status": self.overall_status,
            "risk_score": self.risk_score,
            "bundle_manifest_hash": self.bundle_manifest_hash,
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash
        }

@dataclass
class TraceableFinding:
    """
    Enhanced Finding with full traceability to Phase 4 Policy.
    """
    finding_id: str # Unique ID for this specific finding instance
    fingerprint: str # Stable hash (rule_id + context) to track remediation
    
    # Original Data
    message: str
    severity: str
    
    # Phase 4 Traceability
    policy_id: str # e.g. SEC-PR-002.R1
    parent_policy: str # e.g. SEC-PR-002
    rule_id: str # e.g. R1
    policy_version: str # e.g. 2.0.0
    
    # Compliance Mapping
    compliance: Dict[str, str] # e.g. {"SOC2": "CC6.1"}
    
    # Source Code Pointers
    dsl_source: Optional[str] = None
    compiled_source: Optional[str] = None
    
    # Evidence
    evidence_files: List[str] = field(default_factory=list) # paths in bundle

@dataclass
class ViolationRecord:
    """
    Stable record of a rule violation for lifecycle tracking.
    """
    violation_id: str # SHA256(repo + pr + policy + rule + fingerprint)
    created_at: str
    status: str = "OPEN" # OPEN, REMEDIATED, ACCEPTED

