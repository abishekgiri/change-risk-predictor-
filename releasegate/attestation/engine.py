import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from releasegate.attestation.key_manager import AttestationKeyManager

class AttestationEngine:
    """Core logic for creating and verifying signed attestations."""

    @staticmethod
    def create_attestation(
        tenant_id: str,
        decision: Dict[str, Any],
        private_key: ed25519.Ed25519PrivateKey,
        key_id: str
    ) -> Dict[str, Any]:
        """
        Creates a signed attestation from a decision.
        """
        now = datetime.now(timezone.utc).isoformat()
        attestation_id = str(uuid.uuid4())

        # Construct the assertion payload (what we are signing)
        # We sign valid JSON canonicalization of key fields
        assertion = {
            "release_status": decision.get("release_status"),
            "decision_id": decision.get("decision_id"),
            "policy_hash": decision.get("policy_bundle_hash") or decision.get("policy_hash"),
            "decision_hash": decision.get("decision_hash"),
            "replay_hash": decision.get("replay_hash") or "",
        }

        # Canonicalize for signing
        # We sign the assertion + some metadata to bind context
        signing_payload = {
            "attestation_id": attestation_id,
            "tenant_id": tenant_id,
            "repo": decision.get("repo"),
            "pr_number": decision.get("pr_number"),
            "assertion": assertion,
            "issued_at": now
        }
        
        canonical_bytes = json.dumps(signing_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
        
        # Sign
        signature_bytes = private_key.sign(canonical_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        # Assemble final structure
        attestation = {
            "attestation_id": attestation_id,
            "schema_version": "v1",
            "issued_at": now,
            "issuer": {
                "tenant_id": tenant_id,
                "key_id": key_id
            },
            "subject": {
                "repo": decision.get("repo"),
                "pr_number": decision.get("pr_number"),
                "commit_sha": decision.get("head_sha") or "HEAD"
            },
            "assertion": assertion,
            "signature": {
                "algorithm": "ed25519",
                "value": signature_b64
            }
        }
        
        return attestation

    @staticmethod
    def verify_attestation(attestation: Dict[str, Any], public_key_pem: bytes) -> bool:
        """
        Verifies the signature of an attestation using the provided public key.
        """
        try:
            from cryptography.hazmat.primitives import serialization
            public_key = serialization.load_pem_public_key(public_key_pem)
            
            # Reconstruct signed payload
            signing_payload = {
                "attestation_id": attestation["attestation_id"],
                "tenant_id": attestation["issuer"]["tenant_id"],
                "repo": attestation["subject"]["repo"],
                "pr_number": attestation["subject"]["pr_number"],
                "assertion": attestation["assertion"],
                "issued_at": attestation["issued_at"]
            }
            
            canonical_bytes = json.dumps(signing_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
            signature_bytes = base64.b64decode(attestation["signature"]["value"])
            
            public_key.verify(signature_bytes, canonical_bytes)
            return True
        except (InvalidSignature, Exception):
            return False
