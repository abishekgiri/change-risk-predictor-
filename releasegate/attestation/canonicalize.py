from __future__ import annotations

import json
from typing import Any


def canonicalize_json(value: Any) -> str:
    """
    Canonical JSON encoder used by release attestations.
    - lexicographic key order
    - UTF-8 friendly output
    - minified separators (no whitespace ambiguity)
    """
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonicalize_json_bytes(value: Any) -> bytes:
    return canonicalize_json(value).encode("utf-8")
