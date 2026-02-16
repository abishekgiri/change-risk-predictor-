from __future__ import annotations

from pathlib import Path
from typing import Union


PathLike = Union[str, Path]


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
    base_path = Path(base).resolve(strict=False)
    candidate = base_path.joinpath(*parts)
    resolved = candidate.resolve(strict=False)

    try:
        resolved.relative_to(base_path)
    except Exception as exc:  # ValueError on 3.9; keep broad for safety.
        raise ValueError(f"Path escapes base directory: {resolved}") from exc

    return resolved

