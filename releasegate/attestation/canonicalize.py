from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

from releasegate.attestation.types import ReleaseAttestation


ATTESTATION_SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "release-attestation.v1.json"


class AttestationContractError(ValueError):
    """Raised when an attestation payload violates the frozen v1 contract."""


def _load_attestation_schema(path: Path = ATTESTATION_SCHEMA_PATH) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AttestationContractError(f"Attestation schema file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AttestationContractError(f"Attestation schema is not valid JSON: {path}: {exc}") from exc


def _required_keys(schema: Mapping[str, Any], *, include_signature: bool) -> set[str]:
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(isinstance(k, str) for k in required):
        raise AttestationContractError("Attestation schema 'required' must be a list of strings")
    req = set(required)
    if not include_signature:
        req.discard("signature")
    return req


def _allowed_keys(schema: Mapping[str, Any], *, include_signature: bool) -> set[str]:
    props = schema.get("properties", {})
    if not isinstance(props, dict) or not all(isinstance(k, str) for k in props):
        raise AttestationContractError("Attestation schema 'properties' must be an object with string keys")
    allowed = set(props.keys())
    if not include_signature:
        allowed.discard("signature")
    return allowed


def _validate_const_fields(payload: Mapping[str, Any], schema: Mapping[str, Any], fields: Iterable[str]) -> None:
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return
    for field in fields:
        definition = props.get(field)
        if not isinstance(definition, dict):
            continue
        if "const" not in definition:
            continue
        expected = definition["const"]
        actual = payload.get(field)
        if actual != expected:
            raise AttestationContractError(
                f"Attestation field '{field}' must be {expected!r}, got {actual!r}"
            )


def _validate_attestation_top_level(
    payload: Mapping[str, Any],
    *,
    include_signature: bool,
    schema: Mapping[str, Any],
) -> None:
    if not isinstance(payload, Mapping):
        raise AttestationContractError("Attestation payload must be an object")

    required = _required_keys(schema, include_signature=include_signature)
    missing = [key for key in sorted(required) if key not in payload]
    if missing:
        raise AttestationContractError(f"Attestation payload missing required keys: {missing}")

    # Enforce top-level freeze when schema is strict.
    if schema.get("additionalProperties") is False:
        allowed = _allowed_keys(schema, include_signature=include_signature)
        unknown = [key for key in sorted(payload.keys()) if key not in allowed]
        if unknown:
            raise AttestationContractError(f"Attestation payload has unknown keys: {unknown}")

    # Lock constants at top-level contract fields.
    _validate_const_fields(payload, schema, fields=("schema_version", "attestation_type"))


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


# Backward/interop alias used by external root export path.
def canonical_json_bytes(value: Any) -> bytes:
    return canonicalize_json_bytes(value)


def canonicalize_attestation(attestation: Mapping[str, Any]) -> bytes:
    """
    Canonical bytes for a full release attestation object (including signature).
    This is the single contract-aware entrypoint for attestation canonicalization.
    """
    schema = _load_attestation_schema()
    _validate_attestation_top_level(attestation, include_signature=True, schema=schema)
    try:
        normalized = ReleaseAttestation.model_validate(dict(attestation)).model_dump(mode="json")
    except Exception as exc:
        raise AttestationContractError(f"Attestation payload failed strict model validation: {exc}") from exc
    return canonicalize_json_bytes(normalized)


def canonicalize_attestation_payload(payload_without_signature: Mapping[str, Any]) -> bytes:
    """
    Canonical bytes for the signed attestation payload (signature excluded).
    """
    schema = _load_attestation_schema()
    _validate_attestation_top_level(payload_without_signature, include_signature=False, schema=schema)
    return canonicalize_json_bytes(dict(payload_without_signature))
