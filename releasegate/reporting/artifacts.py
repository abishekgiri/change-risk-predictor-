from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable, List

from releasegate.storage.atomic import atomic_write


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_artifacts_sha256(sha_path: str, files: Iterable[str]) -> List[str]:
    """
    Writes sha256 sums for the provided files in the provided order.

    Returns the list of file paths that were hashed (existing files only).
    """
    existing: List[Path] = []
    for f in files:
        p = Path(str(f))
        if p.exists() and p.is_file():
            existing.append(p)

    if not existing:
        return []

    out_path = Path(sha_path)
    lines = []
    for p in existing:
        digest = _sha256_file(p)
        lines.append(f"{digest}  {p.as_posix()}\n")

    with atomic_write(str(out_path), "w") as f:
        for line in lines:
            f.write(line)

    return [p.as_posix() for p in existing]

