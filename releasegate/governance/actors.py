from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Set


def build_identity_alias_map(raw_aliases: Any) -> Dict[str, str]:
    alias_map: Dict[str, str] = {}
    if not isinstance(raw_aliases, Mapping):
        return alias_map
    for canonical, raw_values in raw_aliases.items():
        canonical_text = str(canonical or "").strip().lower()
        if not canonical_text:
            continue
        alias_map[canonical_text] = canonical_text
        if isinstance(raw_values, (list, tuple, set, frozenset)):
            values = raw_values
        else:
            values = [raw_values]
        for raw in values:
            alias = str(raw or "").strip().lower()
            if alias:
                alias_map[alias] = canonical_text
    return alias_map


def normalize_actor_values(values: Iterable[Any], *, alias_map: Mapping[str, str] | None = None) -> Set[str]:
    normalized: Set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        lowered = text.lower()
        canonical = alias_map.get(lowered, lowered) if alias_map else lowered
        normalized.add(canonical)
    return normalized
