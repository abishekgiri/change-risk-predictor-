from __future__ import annotations

from typing import Any, Dict

from releasegate.attestation.verify import verify_attestation_payload


def verify(attestation: Dict[str, Any], public_keys_by_key_id: Dict[str, str]) -> Dict[str, Any]:
    return verify_attestation_payload(attestation, public_keys_by_key_id=public_keys_by_key_id)


def get_subject(attestation: Dict[str, Any]) -> Dict[str, Any]:
    subject = attestation.get("subject") if isinstance(attestation, dict) else None
    return dict(subject) if isinstance(subject, dict) else {}


def get_decision(attestation: Dict[str, Any]) -> Dict[str, Any]:
    decision = attestation.get("decision") if isinstance(attestation, dict) else None
    return dict(decision) if isinstance(decision, dict) else {}
