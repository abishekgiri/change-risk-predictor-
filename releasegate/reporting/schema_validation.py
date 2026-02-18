from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

from releasegate.utils.json_schema import validate_json_schema_subset


@lru_cache(maxsize=1)
def load_compliance_report_schema() -> Dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[2]
    schema_path = repo_root / "schemas" / "compliance_report.schema.json"
    raw = schema_path.read_text(encoding="utf-8")
    return json.loads(raw)


def validate_compliance_report(report: Dict[str, Any]) -> List[str]:
    schema = load_compliance_report_schema()
    return validate_json_schema_subset(report, schema)

