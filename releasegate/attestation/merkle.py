from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Sequence, Tuple

from releasegate.attestation.canonicalize import canonicalize_json_bytes

LEAF_VERSION = 1
TREE_RULE = "sha256_concat_duplicate_last"


def _normalize_sha256(value: str) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("sha256:"):
        raw = raw.split(":", 1)[1].strip().lower()
    if len(raw) != 64:
        raise ValueError("expected sha256 hex digest")
    return raw


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _leaf_payload(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "leaf_version": int(entry.get("leaf_version") or LEAF_VERSION),
        "attestation_id": str(entry.get("attestation_id") or ""),
        "payload_hash": str(entry.get("payload_hash") or ""),
        "issued_at": str(entry.get("issued_at") or ""),
        "repo": str(entry.get("repo") or ""),
        "commit_sha": str(entry.get("commit_sha") or ""),
        "pr_number": entry.get("pr_number"),
    }


def compute_transparency_leaf_hash(entry: Dict[str, Any]) -> str:
    payload = _leaf_payload(entry)
    canonical = canonicalize_json_bytes(payload)
    return f"sha256:{_sha256_hex(canonical)}"


def _hash_pair(left_hex: str, right_hex: str) -> str:
    left = bytes.fromhex(_normalize_sha256(left_hex))
    right = bytes.fromhex(_normalize_sha256(right_hex))
    return _sha256_hex(left + right)


def merkle_root(leaf_hashes: Sequence[str]) -> str:
    if not leaf_hashes:
        raise ValueError("leaf_hashes must not be empty")
    level = [_normalize_sha256(value) for value in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: List[str] = []
        for i in range(0, len(level), 2):
            next_level.append(_hash_pair(level[i], level[i + 1]))
        level = next_level
    return f"sha256:{level[0]}"


def merkle_inclusion_proof(leaf_hashes: Sequence[str], index: int) -> List[Dict[str, str]]:
    if not leaf_hashes:
        raise ValueError("leaf_hashes must not be empty")
    if index < 0 or index >= len(leaf_hashes):
        raise IndexError("leaf index out of range")

    level = [_normalize_sha256(value) for value in leaf_hashes]
    idx = int(index)
    proof: List[Dict[str, str]] = []

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        if idx % 2 == 0:
            sibling_idx = idx + 1
            side = "right"
        else:
            sibling_idx = idx - 1
            side = "left"

        proof.append({"hash": f"sha256:{level[sibling_idx]}", "side": side})

        next_level: List[str] = []
        for i in range(0, len(level), 2):
            next_level.append(_hash_pair(level[i], level[i + 1]))
        level = next_level
        idx //= 2

    return proof


def verify_merkle_inclusion_proof(
    *,
    leaf_hash: str,
    root_hash: str,
    index: int,
    proof: Sequence[Dict[str, str]],
) -> bool:
    current = _normalize_sha256(leaf_hash)
    idx = int(index)

    for step in proof:
        sibling = _normalize_sha256(str(step.get("hash") or ""))
        side = str(step.get("side") or "").lower()
        if side not in {"left", "right"}:
            return False

        if side == "left":
            current = _hash_pair(sibling, current)
        else:
            current = _hash_pair(current, sibling)
        idx //= 2

    return current == _normalize_sha256(root_hash)


def build_merkle_bundle(entries: Sequence[Dict[str, Any]]) -> Tuple[List[str], str]:
    leaf_hashes = [compute_transparency_leaf_hash(entry) for entry in entries]
    if not leaf_hashes:
        raise ValueError("entries must not be empty")
    return leaf_hashes, merkle_root(leaf_hashes)
