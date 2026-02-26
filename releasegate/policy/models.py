from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet


class PolicyStatus(str, Enum):
    DRAFT = "DRAFT"
    STAGED = "STAGED"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    # Legacy compatibility for older records created before lifecycle hardening.
    DEPRECATED = "DEPRECATED"


ALLOWED_STATUS_TRANSITIONS: Dict[PolicyStatus, FrozenSet[PolicyStatus]] = {
    PolicyStatus.DRAFT: frozenset({PolicyStatus.STAGED, PolicyStatus.ARCHIVED}),
    PolicyStatus.STAGED: frozenset({PolicyStatus.ACTIVE, PolicyStatus.ARCHIVED}),
    PolicyStatus.ACTIVE: frozenset({PolicyStatus.ARCHIVED}),
    PolicyStatus.ARCHIVED: frozenset(),
    PolicyStatus.DEPRECATED: frozenset({PolicyStatus.ACTIVE, PolicyStatus.ARCHIVED}),
}

