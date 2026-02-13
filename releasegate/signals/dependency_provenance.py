"""
Dependency provenance signal: lockfile discovery + deterministic hashing.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence

from releasegate.utils.canonical import canonical_json, sha256_text


LOCKFILE_BASENAMES: Sequence[str] = (
    "package-lock.json",
    "poetry.lock",
    "requirements.txt",
    "Pipfile.lock",
    "go.sum",
    "Cargo.lock",
)


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if value is None:
        return b""
    return str(value).encode("utf-8")


def discover_lockfiles(provider: Any, repo: str, ref: Optional[str]) -> List[str]:
    """
    Discover lockfiles at repo root at the specified ref.
    Returns a stable, sorted list of lockfile paths that exist.
    """
    getter = getattr(provider, "get_file_content", None)
    if not callable(getter):
        return []

    found: List[str] = []
    for name in LOCKFILE_BASENAMES:
        try:
            content = getter(repo, name, ref=ref)
        except Exception:
            content = None
        if content is not None:
            found.append(name)
    return sorted(found)


def hash_lockfiles(
    provider: Any,
    repo: str,
    ref: Optional[str],
    lockfiles: Sequence[str],
) -> List[Dict[str, Any]]:
    """
    Hash discovered lockfiles deterministically.
    Returns stable sorted entries by path.
    """
    getter = getattr(provider, "get_file_content", None)
    if not callable(getter):
        return []

    entries: List[Dict[str, Any]] = []
    for path in sorted(lockfiles):
        try:
            content = getter(repo, path, ref=ref)
        except Exception:
            content = None
        if content is None:
            continue
        data = _to_bytes(content)
        entries.append(
            {
                "path": path,
                "sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
                "size_bytes": len(data),
            }
        )
    return entries


def combined_lockfile_hash(hashes: Sequence[Dict[str, Any]]) -> str:
    payload = [{"path": str(h["path"]), "sha256": str(h["sha256"])} for h in sorted(hashes, key=lambda x: str(x["path"]))]
    return f"sha256:{sha256_text(canonical_json(payload))}"


def build_dependency_provenance_signal(
    *,
    provider: Any,
    repo: str,
    ref: Optional[str],
    lockfile_required: bool,
) -> Dict[str, Any]:
    """
    Build dependency provenance signal.
    """
    lockfiles = discover_lockfiles(provider, repo, ref)
    hashes = hash_lockfiles(provider, repo, ref, lockfiles)
    combined = combined_lockfile_hash(hashes)

    reason_codes: List[str] = []
    satisfied = True
    if lockfile_required and not lockfiles:
        satisfied = False
        reason_codes.append("LOCKFILE_REQUIRED_MISSING")

    return {
        "lockfiles_found": lockfiles,
        "hashes": hashes,
        "combined_hash": combined,
        "lockfile_required": bool(lockfile_required),
        "satisfied": satisfied,
        "reason_codes": reason_codes,
    }
