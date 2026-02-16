from __future__ import annotations

import os


def get_policy_schema_version() -> str:
    """
    Policy schema version identifier embedded into attestations.

    This is intentionally a simple environment-driven value so the attestation
    payload remains deterministic and does not depend on runtime registry state.
    """
    return str(os.getenv("RELEASEGATE_POLICY_SCHEMA_VERSION", "v1")).strip() or "v1"

