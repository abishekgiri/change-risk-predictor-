from __future__ import annotations

from typing import Any, Iterable, Set


def normalize_actor_values(values: Iterable[Any]) -> Set[str]:
    normalized: Set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        normalized.add(text.lower())
    return normalized
