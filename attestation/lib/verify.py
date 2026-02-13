from releasegate.attestation.sdk import get_decision, get_subject, verify

verify_attestation_payload = verify
getSubject = get_subject
getDecision = get_decision

__all__ = ["verify_attestation_payload", "getSubject", "getDecision"]
