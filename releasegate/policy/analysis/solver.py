from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from releasegate.policy.conflict_engine import analyze_policy_conflicts


SCOPE_KEYS = ("org", "project", "workflow", "transition", "environment", "risk_band")


def _normalize_text(value: Any, *, fallback: str = "*") -> str:
    text = str(value or "").strip()
    return text or fallback


def _normalize_result(rule: Dict[str, Any]) -> str:
    result = (
        rule.get("result")
        or (rule.get("enforcement") or {}).get("result")
        or rule.get("action")
        or "UNSPECIFIED"
    )
    return str(result).strip().upper() or "UNSPECIFIED"


def _normalize_require(rule: Dict[str, Any]) -> Dict[str, Any]:
    require = rule.get("require") if isinstance(rule.get("require"), dict) else {}
    approvals = require.get("approvals")
    roles = require.get("roles")
    normalized_roles = sorted({str(role).strip() for role in (roles or []) if str(role).strip()})
    return {
        "approvals": int(approvals) if approvals is not None else None,
        "roles": normalized_roles,
    }


def _extract_scope(rule: Dict[str, Any]) -> Dict[str, str]:
    match_obj = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    scope = {}
    for key in SCOPE_KEYS:
        scope[key] = _normalize_text(match_obj.get(key), fallback="*")
    return scope


def _scope_tuple(scope: Dict[str, str]) -> Tuple[str, ...]:
    return tuple(_normalize_text(scope.get(key), fallback="*") for key in SCOPE_KEYS)


def _scope_covers(a: Dict[str, str], b: Dict[str, str]) -> bool:
    for key in SCOPE_KEYS:
        a_val = _normalize_text(a.get(key), fallback="*")
        b_val = _normalize_text(b.get(key), fallback="*")
        if a_val != "*" and a_val != b_val:
            return False
    return True


def _scope_size(scope: Dict[str, str]) -> int:
    return sum(1 for key in SCOPE_KEYS if _normalize_text(scope.get(key), fallback="*") != "*")


def _fingerprint(material: Dict[str, Any]) -> str:
    payload = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class SolverRule:
    rule_id: str
    index: int
    precedence: int
    scope: Dict[str, str]
    result: str
    require: Dict[str, Any]

    @classmethod
    def from_raw(cls, raw_rule: Dict[str, Any], index: int) -> "SolverRule":
        precedence = raw_rule.get("precedence")
        if precedence is None:
            precedence = index
        return cls(
            rule_id=str(raw_rule.get("id") or f"rule_{index}"),
            index=index,
            precedence=int(precedence),
            scope=_extract_scope(raw_rule),
            result=_normalize_result(raw_rule),
            require=_normalize_require(raw_rule),
        )


def _normalize_rules(policies: List[Dict[str, Any]]) -> List[SolverRule]:
    normalized: List[SolverRule] = []
    index = 0
    for policy in policies:
        rules = policy.get("rules") if isinstance(policy.get("rules"), list) else []
        if not rules:
            controls = policy.get("controls") if isinstance(policy.get("controls"), list) else []
            for control in controls:
                if not isinstance(control, dict):
                    continue
                synthetic = {
                    "id": control.get("id") or f"control_{index}",
                    "match": control.get("match") if isinstance(control.get("match"), dict) else {},
                    "result": control.get("result") or (policy.get("enforcement") or {}).get("result") or "ALLOW",
                    "require": control.get("require") if isinstance(control.get("require"), dict) else {},
                    "precedence": control.get("precedence", index),
                }
                normalized.append(SolverRule.from_raw(synthetic, index))
                index += 1
            continue
        for raw_rule in rules:
            if not isinstance(raw_rule, dict):
                continue
            normalized.append(SolverRule.from_raw(raw_rule, index))
            index += 1
    return normalized


def analyze_policies(
    *,
    policies: List[Dict[str, Any]],
    coverage_targets: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    conflict_report = analyze_policy_conflicts({"rules": [rule for policy in policies for rule in policy.get("rules", [])]})
    rules = _normalize_rules(policies)
    conflicts: List[Dict[str, Any]] = []
    ambiguities: List[Dict[str, Any]] = []
    shadowed_rules: List[Dict[str, Any]] = []

    for idx, left in enumerate(rules):
        for right in rules[idx + 1 :]:
            if _scope_tuple(left.scope) != _scope_tuple(right.scope):
                continue
            requirement_conflict = left.require != right.require
            outcome_conflict = left.result != right.result
            if outcome_conflict or requirement_conflict:
                conflict_id = f"conf_{_fingerprint({'left': left.rule_id, 'right': right.rule_id, 'scope': left.scope})}"
                conflict_item = {
                    "conflict_id": conflict_id,
                    "type": "CONTRADICTION" if outcome_conflict else "REQUIREMENT_CONFLICT",
                    "scope": left.scope,
                    "left_rule_id": left.rule_id,
                    "right_rule_id": right.rule_id,
                    "left_result": left.result,
                    "right_result": right.result,
                    "left_require": left.require,
                    "right_require": right.require,
                }
                conflicts.append(conflict_item)
                if left.precedence == right.precedence:
                    ambiguities.append(
                        {
                            "ambiguity_id": f"amb_{conflict_id}",
                            "conflict_id": conflict_id,
                            "scope": left.scope,
                            "reason": "same_precedence_overlap",
                            "rule_ids": [left.rule_id, right.rule_id],
                        }
                    )

    ordered = sorted(rules, key=lambda item: (item.precedence, item.index))
    for idx, current in enumerate(ordered):
        for prior in ordered[:idx]:
            if prior.precedence > current.precedence:
                continue
            if not _scope_covers(prior.scope, current.scope):
                continue
            if _scope_size(prior.scope) <= _scope_size(current.scope):
                shadowed_rules.append(
                    {
                        "rule_id": current.rule_id,
                        "shadowed_by": prior.rule_id,
                        "scope": current.scope,
                        "reason": "broader_preceding_rule",
                    }
                )
                break

    gaps: List[Dict[str, Any]] = []
    required_targets = coverage_targets or []
    for target in required_targets:
        if not isinstance(target, dict):
            continue
        normalized_scope = {key: _normalize_text(target.get(key), fallback="*") for key in SCOPE_KEYS}
        if any(_scope_covers(rule.scope, normalized_scope) for rule in rules):
            continue
        gap_id = f"gap_{_fingerprint(normalized_scope)}"
        gaps.append(
            {
                "gap_id": gap_id,
                "scope": normalized_scope,
                "reason": "target_not_covered",
            }
        )

    # Preserve existing lint-style findings where available.
    for contradiction in conflict_report.get("contradictions") or []:
        if not isinstance(contradiction, dict):
            continue
        conflicts.append(
            {
                "conflict_id": f"lint_{_fingerprint(contradiction)}",
                "type": "LINT_CONTRADICTION",
                "details": contradiction,
            }
        )
    for gap in conflict_report.get("coverage_gaps") or []:
        if not isinstance(gap, dict):
            continue
        gaps.append(
            {
                "gap_id": f"lint_gap_{_fingerprint(gap)}",
                "scope": gap.get("scope") if isinstance(gap.get("scope"), dict) else {},
                "reason": "lint_coverage_gap",
                "details": gap,
            }
        )
    for shadowed in conflict_report.get("shadowed_rules") or []:
        if isinstance(shadowed, dict):
            shadowed_rules.append(shadowed)

    unreachable_rules = [
        {
            "rule_id": item.get("rule_id"),
            "reason": item.get("reason", "shadowed"),
            "shadowed_by": item.get("shadowed_by"),
        }
        for item in shadowed_rules
        if item.get("rule_id")
    ]

    seen: set[str] = set()
    deduped_conflicts: List[Dict[str, Any]] = []
    for item in conflicts:
        conflict_id = str(item.get("conflict_id") or "")
        if not conflict_id or conflict_id in seen:
            continue
        seen.add(conflict_id)
        deduped_conflicts.append(item)

    seen.clear()
    deduped_gaps: List[Dict[str, Any]] = []
    for item in gaps:
        gap_id = str(item.get("gap_id") or "")
        if not gap_id or gap_id in seen:
            continue
        seen.add(gap_id)
        deduped_gaps.append(item)

    return {
        "summary": {
            "policy_count": len(policies),
            "rule_count": len(rules),
            "conflict_count": len(deduped_conflicts),
            "gap_count": len(deduped_gaps),
            "ambiguity_count": len(ambiguities),
            "shadowed_rule_count": len(shadowed_rules),
            "unreachable_rule_count": len(unreachable_rules),
        },
        "conflicts": deduped_conflicts,
        "gaps": deduped_gaps,
        "ambiguities": ambiguities,
        "shadowed_rules": shadowed_rules,
        "unreachable_rules": unreachable_rules,
    }


def explain_conflict(*, report: Dict[str, Any], conflict_id: str) -> Dict[str, Any]:
    for conflict in report.get("conflicts") or []:
        if str(conflict.get("conflict_id") or "") != str(conflict_id or ""):
            continue
        conflict_type = str(conflict.get("type") or "CONFLICT").upper()
        if conflict_type in {"CONTRADICTION", "LINT_CONTRADICTION"}:
            suggestion = "Align overlapping rules to one outcome or narrow one rule scope."
        elif conflict_type in {"REQUIREMENT_CONFLICT"}:
            suggestion = "Normalize approval requirements for overlapping scope."
        else:
            suggestion = "Review scope overlap and precedence ordering."
        return {
            "conflict_id": conflict.get("conflict_id"),
            "type": conflict.get("type"),
            "scope": conflict.get("scope"),
            "left_rule_id": conflict.get("left_rule_id"),
            "right_rule_id": conflict.get("right_rule_id"),
            "details": conflict.get("details"),
            "suggestion": suggestion,
        }
    raise ValueError("conflict not found")


def _load_yaml_or_json(path: Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    parsed: Any
    if path.suffix.lower() in {".yaml", ".yml"}:
        parsed = yaml.safe_load(raw) or {}
    else:
        parsed = json.loads(raw or "{}")
    if not isinstance(parsed, dict):
        raise ValueError(f"policy file `{path}` must contain a JSON/YAML object")
    return parsed


def load_policies_from_path(path: str) -> List[Dict[str, Any]]:
    root = Path(path)
    if not root.exists():
        raise ValueError(f"policies path does not exist: {path}")
    candidates: List[Path] = []
    if root.is_file():
        candidates = [root]
    else:
        for ext in ("*.json", "*.yaml", "*.yml"):
            candidates.extend(sorted(root.rglob(ext)))
    policies: List[Dict[str, Any]] = []
    for candidate in candidates:
        try:
            loaded = _load_yaml_or_json(candidate)
        except Exception:
            continue
        loaded["_source_path"] = str(candidate)
        policies.append(loaded)
    if not policies:
        raise ValueError(f"no policy objects found at {path}")
    return policies
