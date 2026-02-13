from __future__ import annotations

from typing import Any, Dict

from releasegate.attestation.crypto import load_public_keys_map
from releasegate.attestation.verify import verify_attestation_payload


def verify(attestation: Dict[str, Any]) -> Dict[str, Any]:
    return verify_attestation_payload(
        attestation,
        public_keys_by_key_id=load_public_keys_map(),
    )
