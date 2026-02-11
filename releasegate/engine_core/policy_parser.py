import hashlib
import json
from typing import Any, Dict, List, Optional, Set

from releasegate.policy.policy_types import Policy


def compute_policy_hash(policies: List[Policy]) -> str:
    canonical = []
    for policy in sorted(policies, key=lambda p: p.policy_id):
        canonical.append(policy.model_dump(mode="json", exclude_none=True))
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def check_condition(actual: Any, operator: str, expected: Any) -> bool:
    if actual is None:
        return False
    try:
        if operator == "==":
            return actual == expected
        if operator == "!=":
            return actual != expected
        if operator == ">":
            return float(actual) > float(expected)
        if operator == ">=":
            return float(actual) >= float(expected)
        if operator == "<":
            return float(actual) < float(expected)
        if operator == "<=":
            return float(actual) <= float(expected)
        if operator == "in":
            if isinstance(actual, (list, tuple, set)):
                return any(a in expected for a in actual)
            return actual in expected
        if operator == "not in":
            if isinstance(actual, (list, tuple, set)):
                return all(a not in expected for a in actual)
            return actual not in expected
    except Exception:
        return False
    return False


def flatten_signals(
    data: Dict[str, Any],
    prefix: str = "",
    preserve_keys: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """
    Recursive flatten for dot-notation signal lookup.
    """
    preserve = preserve_keys or {"files_changed"}
    out: Dict[str, Any] = {}
    for key, value in data.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict) and key not in preserve:
            out.update(flatten_signals(value, full_key, preserve_keys=preserve))
        else:
            out[full_key] = value
    return out
