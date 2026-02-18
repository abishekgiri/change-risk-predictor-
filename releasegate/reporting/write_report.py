from __future__ import annotations

import json
from typing import Any, Dict

from releasegate.storage.atomic import atomic_write


def write_json_report_atomic(path: str, payload: Dict[str, Any]) -> None:
    """
    Atomic JSON writer for CI-facing reports.

    Writes UTF-8 bytes with stable key ordering so downstream tools can hash
    and diff reports reliably.
    """
    data = json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    with atomic_write(path, "wb") as f:
        f.write(data)

