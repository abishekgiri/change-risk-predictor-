from __future__ import annotations

import importlib.resources as resources
import json
from functools import lru_cache
from typing import Any, Dict, List

from releasegate.utils.json_schema import validate_json_schema_subset


@lru_cache(maxsize=1)
def load_compliance_report_schema() -> Dict[str, Any]:
    # Read from the packaged data dir (releasegate/schemas/) via
    # importlib.resources so this works from an installed wheel, not just
    # a dev checkout.  Previously used a repo-root-relative path that
    # broke on `pip install` (the 2026-06-03 readiness-audit re-test).
    ref = resources.files("releasegate.schemas").joinpath("compliance_report.schema.json")
    return json.loads(ref.read_text(encoding="utf-8"))


def validate_compliance_report(report: Dict[str, Any]) -> List[str]:
    schema = load_compliance_report_schema()
    return validate_json_schema_subset(report, schema)

