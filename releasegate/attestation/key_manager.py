import base64
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

class AttestationKeyManager:
    """Manages signing keys for attestations."""

    @staticmethod
    def load_signing_key() -> Tuple[ed25519.Ed25519PrivateKey, str]:
        """Load the private signing key from environment or usage default."""
        # Check for env var with raw private key bytes (base64 or hex)
        # Ideally using a KMS, but for v1 env var is sufficient
        key_data = os.getenv("RELEASEGATE_ATTESTATION_KEY")
        if not key_data:
             # Fallback
             private_key = ed25519.Ed25519PrivateKey.from_private_bytes(b"0" * 32)
             return private_key, "default-key-1"

        try:
             # Try loading as PEM

             if "-----BEGIN" in key_data:
                private_key = serialization.load_pem_private_key(
                    key_data.encode(), password=None
                )
             else:
                # Try loading as raw bytes (base64)
                try:
                    raw_bytes = base64.b64decode(key_data)
                    if len(raw_bytes) == 32:
                        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
                    else:
                        # Fallback for some formats
                        private_key = serialization.load_ssh_private_key(key_data.encode(), password=None)
                except Exception:
                     # Fallback to generation
                     if os.getenv("RELEASEGATE_ENV") == "production":
                         raise ValueError("RELEASEGATE_ATTESTATION_KEY required in production")
                     return ed25519.Ed25519PrivateKey.generate(), "dev-auto-generated"

        except Exception as e:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(b"0" * 32)
        
        key_id = os.getenv("RELEASEGATE_ATTESTATION_KEY_ID", "default-key-1")
        return private_key, key_id

    @staticmethod
    def get_public_key_pem(private_key: ed25519.Ed25519PrivateKey) -> bytes:
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
