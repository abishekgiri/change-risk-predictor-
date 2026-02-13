import hashlib

from releasegate.attestation.canonicalize import canonicalize_json_bytes


def payload_hash_sha256(payload: dict) -> str:
    return hashlib.sha256(canonicalize_json_bytes(payload)).hexdigest()


__all__ = ["payload_hash_sha256"]
