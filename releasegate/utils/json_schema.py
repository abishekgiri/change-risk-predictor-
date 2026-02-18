from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union


JsonSchema = Dict[str, Any]


def _type_matches(value: Any, schema_type: str) -> bool:
    if schema_type == "null":
        return value is None
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "integer":
        # bool is a subclass of int; reject it explicitly.
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return (isinstance(value, (int, float)) and not isinstance(value, bool))
    if schema_type == "object":
        return isinstance(value, dict)
    if schema_type == "array":
        return isinstance(value, list)
    # Unknown / unsupported type in our minimal validator.
    return False


def _normalize_types(raw: Any) -> Optional[List[str]]:
    if raw is None:
        return None
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list) and all(isinstance(x, str) for x in raw):
        return list(raw)
    return None


def validate_json_schema_subset(instance: Any, schema: JsonSchema, *, path: str = "$") -> List[str]:
    """
    Minimal JSON Schema validator for the subset of draft-07 used by this repo.

    Supported keywords:
      - type (string or list of strings)
      - const
      - enum
      - properties
      - required
      - additionalProperties (bool)
      - items
    """
    errors: List[str] = []

    allowed_types = _normalize_types(schema.get("type"))
    if allowed_types is not None:
        if not any(_type_matches(instance, t) for t in allowed_types):
            errors.append(f"{path}: expected type {allowed_types}, got {type(instance).__name__}")
            return errors  # Type mismatch: stop descending.

    if "const" in schema:
        expected = schema.get("const")
        if instance != expected:
            errors.append(f"{path}: expected const {expected!r}, got {instance!r}")
            return errors

    enum = schema.get("enum")
    if isinstance(enum, list):
        if instance not in enum:
            errors.append(f"{path}: expected one of {enum!r}, got {instance!r}")
            return errors

    # Descend by structural type.
    if isinstance(instance, dict):
        props = schema.get("properties")
        required = schema.get("required")
        additional = schema.get("additionalProperties")

        if isinstance(required, list):
            for key in required:
                if isinstance(key, str) and key not in instance:
                    errors.append(f"{path}: missing required key {key!r}")

        if additional is False and isinstance(props, dict):
            allowed = set(k for k in props.keys() if isinstance(k, str))
            for key in instance.keys():
                if key not in allowed:
                    errors.append(f"{path}: unknown key {key!r} (additionalProperties=false)")

        if isinstance(props, dict):
            for key, subschema in props.items():
                if not isinstance(key, str) or not isinstance(subschema, dict):
                    continue
                if key not in instance:
                    continue
                errors.extend(validate_json_schema_subset(instance[key], subschema, path=f"{path}.{key}"))
        return errors

    if isinstance(instance, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for idx, item in enumerate(instance):
                errors.extend(validate_json_schema_subset(item, items, path=f"{path}[{idx}]"))
        return errors

    return errors

