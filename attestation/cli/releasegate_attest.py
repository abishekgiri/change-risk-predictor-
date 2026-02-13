#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from releasegate.attestation.crypto import load_public_keys_map
from releasegate.attestation.verify import verify_attestation_payload


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: releasegate-attest <attestation.json>")
        return 2
    path = Path(sys.argv[1])
    payload = json.loads(path.read_text(encoding="utf-8"))
    report = verify_attestation_payload(
        payload,
        public_keys_by_key_id=load_public_keys_map(),
    )
    print(json.dumps(report, indent=2))
    ok = (
        report.get("schema_valid")
        and report.get("payload_hash_match")
        and report.get("trusted_issuer")
        and report.get("valid_signature")
    )
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
