#!/usr/bin/env python3
from __future__ import annotations

import json
import sys

from releasegate.policy.lint import format_lint_report, lint_compiled_policies


def main() -> int:
    report = lint_compiled_policies(policy_dir="releasegate/policy/compiled", strict_schema=True)
    if report.get("ok"):
        print(format_lint_report(report))
        return 0
    print(format_lint_report(report), file=sys.stderr)
    print(json.dumps(report, indent=2), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
