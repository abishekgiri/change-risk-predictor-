import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from releasegate.storage import get_storage_backend

def record_release_attestation(
    decision_id: str,
    tenant_id: str,
    repo: str,
    pr_number: Optional[int],
    attestation: Dict[str, Any]
) -> str:
    """
    Persists a signed release attestation to the audit log.
    Returns the attestation_id.
    """
    storage = get_storage_backend()
    
    attestation_id = attestation["attestation_id"]
    schema_version = attestation["schema_version"]
    key_id = attestation["issuer"]["key_id"]
    algorithm = attestation["signature"]["algorithm"]
    
    # We use the signature value as the "signed payload hash" proxy for v1 uniqueness/indexing 
    # or arguably we should hash the 'assertion' part. 
    # The schema asks for "signed_payload_hash". 
    # Let's use the signature for now as it unique to the payload+key.
    signed_payload_hash = attestation["signature"]["value"]
    
    attestation_json = json.dumps(attestation, sort_keys=True)
    created_at = datetime.now(timezone.utc).isoformat()
    
    storage.execute(
        """
        INSERT INTO audit_attestations (
            tenant_id, attestation_id, decision_id, repo, pr_number,
            schema_version, key_id, algorithm, signed_payload_hash,
            attestation_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, attestation_id) DO NOTHING
        """,
        (
            tenant_id,
            attestation_id,
            decision_id,
            repo,
            pr_number,
            schema_version,
            key_id,
            algorithm,
            signed_payload_hash,
            attestation_json,
            created_at
        )
    )
    
    return attestation_id
