from typing import Any, Dict, Optional

from releasegate.attestation.engine import AttestationEngine
from releasegate.attestation.key_manager import AttestationKeyManager
from releasegate.decision.types import Decision

def build_bundle_from_decision(
    decision: Decision,
    repo: str,
    pr_number: Optional[int],
    engine_version: str
) -> Dict[str, Any]:
    """
    Constructs the un-signed bundle payload from a decision.
    In v1, this essentially just passes the decision through, 
    but allows for future bundle expansion (e.g. including policy text).
    """
    # For now, the bundle is the decision itself + context
    bundle = decision.model_dump(mode="json")
    bundle["repo"] = repo
    bundle["pr_number"] = pr_number
    bundle["engine_version"] = engine_version
    return bundle

def build_attestation_from_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Signs the bundle to create a release attestation.
    """
    private_key, key_id = AttestationKeyManager.load_signing_key()
    
    # We need to adapt the bundle back to what engine expects or update engine
    # Engine expects "tenant_id" and "decision" dict.
    
    # Extract tenant_id from bundle or env
    tenant_id = bundle.get("tenant_id", "default")
    
    # Create the attestation
    attestation = AttestationEngine.create_attestation(
        tenant_id=tenant_id,
        decision=bundle,
        private_key=private_key,
        key_id=key_id
    )
    return attestation
