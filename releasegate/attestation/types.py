from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class DecisionBundle(BaseModel):
    """
    Single immutable input to the attestation layer.
    Attestation generators consume this object and never query providers directly.
    """

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    decision_id: str
    repo: str
    pr_number: Optional[int] = None
    release_id: Optional[str] = None
    build_id: Optional[str] = None
    commit_sha: str = "unknown"
    merge_sha: Optional[str] = None
    policy_version: str
    policy_hash: str
    policy_bundle_hash: str
    policy_scope: List[str] = Field(default_factory=list)
    policy_resolution_hash: Optional[str] = None
    signals: Dict[str, Any] = Field(default_factory=dict)
    risk_score: Optional[float] = None
    decision: Literal["ALLOW", "BLOCK"]
    reason_codes: List[str] = Field(default_factory=list)
    timestamp: str
    engine_version: str
    checkpoint_hashes: List[str] = Field(default_factory=list)


class AttestationSubject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    commit_sha: str
    merge_sha: Optional[str] = None
    pr_number: Optional[int] = None
    build_id: Optional[str] = None
    release_id: Optional[str] = None


class AttestationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_version: str
    policy_hash: str
    policy_bundle_hash: str
    policy_scope: List[str] = Field(default_factory=list)
    policy_resolution_hash: Optional[str] = None


class AttestationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["ALLOW", "BLOCK"]
    risk_score: Optional[float] = None
    reason_codes: List[str] = Field(default_factory=list)


class AttestationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signals_summary: Dict[str, Any] = Field(default_factory=dict)
    dependency_provenance: Dict[str, Any] = Field(default_factory=dict)
    checkpoint_hashes: List[str] = Field(default_factory=list)
    decision_bundle_hash: str


class AttestationIssuer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_id: str
    app_id: str
    environment: str
    key_id: str


class AttestationSignature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algorithm: Literal["ed25519"]
    signed_payload_hash: str
    signature_bytes: str


class ReleaseAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0.0"]
    attestation_type: Literal["releasegate.release_attestation"]
    issued_at: str
    tenant_id: str
    decision_id: str
    engine_version: str
    subject: AttestationSubject
    policy: AttestationPolicy
    decision: AttestationDecision
    evidence: AttestationEvidence
    issuer: AttestationIssuer
    signature: AttestationSignature


class VerifyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_valid: bool
    payload_hash_match: bool
    trusted_issuer: bool
    valid_signature: bool
    errors: List[str] = Field(default_factory=list)
    signed_payload_hash: Optional[str] = None
    computed_payload_hash: Optional[str] = None
    key_id: Optional[str] = None
