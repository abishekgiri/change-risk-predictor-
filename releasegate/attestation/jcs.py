from __future__ import annotations

import json
import math
from typing import Any


class JCSCanonicalizationError(ValueError):
    pass


def _escape_string(value: str) -> str:
    # json.dumps on a string produces a JSON string with proper escaping.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _canonical_number(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        raise JCSCanonicalizationError("non-number passed to number encoder")

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        if not math.isfinite(value):
            raise JCSCanonicalizationError("non-finite float is not allowed in canonical JSON")

        # Match JavaScript (-0).toString() => "0"
        if value == 0.0:
            return "0"

        # Prefer integer form when the float is an integer and reasonably sized.
        if value.is_integer() and abs(value) < 1e21:
            return str(int(value))

        text = repr(value)
        if text.endswith(".0"):
            text = text[:-2]
        return text

    raise JCSCanonicalizationError(f"unsupported number type: {type(value).__name__}")


def _canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"

    if isinstance(value, str):
        return _escape_string(value)

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _canonical_number(value)

    if isinstance(value, list):
        return "[" + ",".join(_canonicalize(item) for item in value) + "]"

    if isinstance(value, dict):
        items: list[str] = []
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise JCSCanonicalizationError("object keys must be strings")
            items.append(_escape_string(key) + ":" + _canonicalize(value[key]))
        return "{" + ",".join(items) + "}"

    raise JCSCanonicalizationError(f"unsupported type for canonical JSON: {type(value).__name__}")


def canonicalize_jcs(value: Any) -> str:
    """
    Canonical JSON text intended to follow RFC 8785 (JCS) for the subset of
    JSON types ReleaseGate emits (objects, arrays, strings, numbers, booleans,
    null). Non-finite floats are rejected.
    """
    return _canonicalize(value)


def canonicalize_jcs_bytes(value: Any) -> bytes:
    return canonicalize_jcs(value).encode("utf-8")

