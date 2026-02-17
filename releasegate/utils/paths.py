from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from typing import Union


PathLike = Union[str, Path]


class UnsafePathError(ValueError):
    """Raised when a path would escape its intended base directory."""


_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:$")


def _iter_safe_segments(part: PathLike) -> list[str]:
    """
    Split a user-provided path part into safe segments.

    We treat both "/" and "\\" as separators and reject:
    - absolute paths
    - ".." traversal
    - Windows drive roots like "C:"

    "." / empty are treated as no-ops (common from Path.relative_to()).
    """
    raw = str(part).strip()
    if raw in ("", "."):
        return []

    raw = raw.replace("\\", "/")
    p = PurePosixPath(raw)

    if p.is_absolute():
        raise UnsafePathError("Absolute paths are not allowed.")

    segments = list(p.parts)
    for seg in segments:
        if seg == "..":
            raise UnsafePathError("Path traversal ('..') is not allowed.")
        if _WIN_DRIVE_RE.match(seg):
            raise UnsafePathError("Windows drive paths are not allowed.")

    return segments


def safe_join_under(base: PathLike, *parts: PathLike) -> Path:
    """
    Join path parts under a base directory, preventing path traversal and
    symlink-based escapes.

    Returns a resolved absolute Path that is guaranteed to be inside base.

    Notes:
    - This prevents '../' traversal and absolute-path overrides.
    - This rejects symlinks that resolve outside the base directory.
    - This does not eliminate TOCTOU races for attacker-controlled filesystems,
      but is sufficient for typical config/policy file loading.
    """
    base_path = os.path.realpath(str(base))

    safe_segments: list[str] = []
    for part in parts:
        safe_segments.extend(_iter_safe_segments(part))

    candidate = os.path.normpath(os.path.join(base_path, *safe_segments))
    resolved = os.path.realpath(candidate)

    try:
        if os.path.commonpath([resolved, base_path]) != base_path:
            raise UnsafePathError(f"Path escapes base directory: {resolved}")
    except Exception as exc:
        raise UnsafePathError(f"Path escapes base directory: {resolved}") from exc

    return Path(resolved)
