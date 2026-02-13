from releasegate.attestation.crypto import current_key_id, load_private_key_from_env, sign_bytes


def sign_payload_hash(payload_hash_hex: str) -> dict:
    private_key = load_private_key_from_env()
    return {
        "algorithm": "ed25519",
        "key_id": current_key_id(),
        "signature_bytes": sign_bytes(private_key, payload_hash_hex),
    }


__all__ = ["sign_payload_hash"]
