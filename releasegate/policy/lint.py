from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from releasegate.policy.loader import PolicyLoader
from releasegate.policy.policy_types import Policy
from releasegate.utils.paths import safe_join_under


def _issue(
    severity: str,
    code: str,
    message: str,
    *,
    policy_id: Optional[str] = None,
    source_file: Optional[str] = None,
) -> Dict[str, Any]:
    issue = {
        "severity": severity,
        "code": code,
        "message": message,
    }
    if policy_id:
        issue["policy_id"] = policy_id
    if source_file:
        issue["source_file"] = source_file
    return issue


def _iter_policy_yaml(policy_dir: str) -> List[Tuple[str, Dict[str, Any]]]:
    docs: List[Tuple[str, Dict[str, Any]]] = []
    policy_base = Path(policy_dir).resolve(strict=False)
    if not policy_base.exists():
        return docs
    for root, _, files in os.walk(policy_base):
        root_path = Path(root)
        for file_name in sorted(files):
            if file_name.startswith("_") or not file_name.endswith((".yaml", ".yml")):
                continue
            try:
                rel_root = root_path.relative_to(policy_base)
                full_path = safe_join_under(policy_base, rel_root, file_name)
            except ValueError:
                continue
            with full_path.open("r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                docs.append((str(full_path), loaded))
    return docs


def _is_number(value: Any) -> bool:
    try:
        float(value)
        return True
    except Exception:
        return False


def _control_signature(control: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(control.get("signal")),
        str(control.get("operator")),
        json.dumps(control.get("value"), sort_keys=True, separators=(",", ":")),
    )


def _check_internal_contradictions(policy: Policy, source_file: Optional[str]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    by_signal: Dict[str, List[Dict[str, Any]]] = {}
    controls = [c.model_dump(mode="json") for c in policy.controls]
    for ctrl in controls:
        by_signal.setdefault(ctrl["signal"], []).append(ctrl)

    for signal, entries in by_signal.items():
        equals = [c["value"] for c in entries if c["operator"] == "=="]
        not_equals = [c["value"] for c in entries if c["operator"] == "!="]
        in_values = [c["value"] for c in entries if c["operator"] == "in" and isinstance(c["value"], list)]
        not_in_values = [c["value"] for c in entries if c["operator"] == "not in" and isinstance(c["value"], list)]

        if len({json.dumps(v, sort_keys=True) for v in equals}) > 1:
            issues.append(
                _issue(
                    "ERROR",
                    "CONTRADICTORY_EQUALITY",
                    f"Signal `{signal}` has multiple incompatible equality constraints.",
                    policy_id=policy.policy_id,
                    source_file=source_file,
                )
            )
        for eq_val in equals:
            if any(eq_val == ne for ne in not_equals):
                issues.append(
                    _issue(
                        "ERROR",
                        "CONTRADICTORY_EQUALITY_NEGATION",
                        f"Signal `{signal}` requires and forbids the same value `{eq_val}`.",
                        policy_id=policy.policy_id,
                        source_file=source_file,
                    )
                )
                break

        if in_values and not_in_values:
            combined_in = set().union(*[set(v) for v in in_values])
            combined_not_in = set().union(*[set(v) for v in not_in_values])
            if combined_in and combined_in.issubset(combined_not_in):
                issues.append(
                    _issue(
                        "ERROR",
                        "CONTRADICTORY_IN_NOT_IN",
                        f"Signal `{signal}` `in` values are fully excluded by `not in`.",
                        policy_id=policy.policy_id,
                        source_file=source_file,
                    )
                )

        lower_value: Optional[float] = None
        lower_inclusive = True
        upper_value: Optional[float] = None
        upper_inclusive = True
        has_numeric_bounds = False

        for c in entries:
            op = c["operator"]
            value = c["value"]
            if op not in {">", ">=", "<", "<="} or not _is_number(value):
                continue
            has_numeric_bounds = True
            v = float(value)
            if op in {">", ">="}:
                inclusive = op == ">="
                if lower_value is None or v > lower_value or (v == lower_value and not inclusive and lower_inclusive):
                    lower_value = v
                    lower_inclusive = inclusive
            else:
                inclusive = op == "<="
                if upper_value is None or v < upper_value or (v == upper_value and not inclusive and upper_inclusive):
                    upper_value = v
                    upper_inclusive = inclusive

        if has_numeric_bounds and lower_value is not None and upper_value is not None:
            if lower_value > upper_value or (lower_value == upper_value and (not lower_inclusive or not upper_inclusive)):
                issues.append(
                    _issue(
                        "ERROR",
                        "CONTRADICTORY_NUMERIC_BOUNDS",
                        f"Signal `{signal}` has mutually exclusive numeric bounds.",
                        policy_id=policy.policy_id,
                        source_file=source_file,
                    )
                )

    return issues


def lint_compiled_policies(policy_dir: str = "releasegate/policy/compiled", strict_schema: bool = True) -> Dict[str, Any]:
    issues: List[Dict[str, Any]] = []
    raw_docs = _iter_policy_yaml(policy_dir)
    by_policy_id: Dict[str, List[str]] = {}

    for source_file, doc in raw_docs:
        policy_id = doc.get("policy_id")
        if policy_id:
            by_policy_id.setdefault(str(policy_id), []).append(source_file)

    for policy_id, files in by_policy_id.items():
        if len(files) > 1:
            issues.append(
                _issue(
                    "ERROR",
                    "DUPLICATE_POLICY_ID",
                    f"Policy ID `{policy_id}` is declared in multiple files.",
                    policy_id=policy_id,
                    source_file=", ".join(files),
                )
            )

    loader = PolicyLoader(policy_dir=policy_dir, schema="compiled", strict=strict_schema)
    try:
        loaded = loader.load_all()
        policies = [p for p in loaded if isinstance(p, Policy)]
    except Exception as exc:
        issues.append(
            _issue(
                "ERROR",
                "SCHEMA_VALIDATION_FAILED",
                f"Compiled policy schema validation failed: {exc}",
            )
        )
        return {
            "ok": False,
            "policy_dir": policy_dir,
            "policy_count": 0,
            "error_count": 1,
            "warning_count": 0,
            "issues": issues,
        }

    source_by_id = {}
    for source_file, doc in raw_docs:
        pid = doc.get("policy_id")
        if pid:
            source_by_id[str(pid)] = source_file

    signature_map: Dict[str, List[Policy]] = {}
    has_risk_controls = False
    block_policy_count = 0
    for policy in policies:
        source_file = source_by_id.get(policy.policy_id)
        issues.extend(_check_internal_contradictions(policy, source_file))

        controls = [c.model_dump(mode="json") for c in policy.controls]
        for c in controls:
            signal = str(c.get("signal"))
            if signal.startswith("risk.") or signal.startswith("core_risk."):
                has_risk_controls = True

        if policy.enforcement.result == "BLOCK":
            block_policy_count += 1

        signature = json.dumps(sorted([_control_signature(c) for c in controls]), separators=(",", ":"))
        signature_map.setdefault(signature, []).append(policy)

    for overlapping in signature_map.values():
        if len(overlapping) <= 1:
            continue
        results = {p.enforcement.result for p in overlapping}
        if len(results) > 1:
            ids = ", ".join(sorted(p.policy_id for p in overlapping))
            issues.append(
                _issue(
                    "ERROR",
                    "AMBIGUOUS_OVERLAP",
                    f"Policies share identical triggers but different enforcement results: {ids}.",
                )
            )

    if policies and not has_risk_controls:
        issues.append(
            _issue(
                "WARNING",
                "NO_RISK_CONTROL",
                "No compiled policy references `risk.*` or `core_risk.*` signals.",
            )
        )
    if policies and block_policy_count == 0:
        issues.append(
            _issue(
                "WARNING",
                "NO_BLOCK_POLICY",
                "No compiled policies produce `BLOCK`; enforcement may be advisory only.",
            )
        )

    error_count = sum(1 for i in issues if i["severity"] == "ERROR")
    warning_count = sum(1 for i in issues if i["severity"] == "WARNING")
    return {
        "ok": error_count == 0,
        "policy_dir": policy_dir,
        "policy_count": len(policies),
        "error_count": error_count,
        "warning_count": warning_count,
        "issues": issues,
    }


def format_lint_report(report: Dict[str, Any]) -> str:
    status = "PASS" if report.get("ok") else "FAIL"
    lines = [
        f"Policy Lint: {status}",
        f"Policy Dir: {report.get('policy_dir')}",
        f"Policies: {report.get('policy_count', 0)}",
        f"Errors: {report.get('error_count', 0)}",
        f"Warnings: {report.get('warning_count', 0)}",
    ]
    issues = report.get("issues") or []
    if issues:
        lines.append("")
        lines.append("Issues:")
        for issue in issues:
            location = ""
            if issue.get("policy_id"):
                location += f" policy={issue['policy_id']}"
            if issue.get("source_file"):
                location += f" file={issue['source_file']}"
            lines.append(
                f"- [{issue.get('severity')}] {issue.get('code')}: {issue.get('message')}{location}"
            )
    return "\n".join(lines)
