from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from releasegate.policy.registry import get_registry_policy
from releasegate.storage import get_storage_backend
from releasegate.storage.base import resolve_tenant_id
from releasegate.storage.schema import init_db
from releasegate.utils.canonical import canonical_json, sha256_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _parse_json(value: Any, fallback: Any) -> Any:
    if isinstance(value, type(fallback)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return fallback
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, type(fallback)):
                return parsed
        except json.JSONDecodeError:
            return fallback
    return fallback


def _policy_by_id_and_version(*, tenant_id: str, policy_id: str, version: int) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    row = storage.fetchone(
        """
        SELECT tenant_id, policy_id, version, status, policy_hash, policy_json, scope_type, scope_id
        FROM policy_registry_entries
        WHERE tenant_id = ? AND policy_id = ? AND version = ?
        LIMIT 1
        """,
        (tenant_id, _normalize_text(policy_id), int(version)),
    )
    if not row:
        return None
    return {
        "tenant_id": row.get("tenant_id"),
        "policy_id": row.get("policy_id"),
        "version": int(row.get("version") or 0),
        "status": _normalize_text(row.get("status")),
        "policy_hash": _normalize_text(row.get("policy_hash")),
        "policy_json": _parse_json(row.get("policy_json"), {}),
        "scope_type": _normalize_text(row.get("scope_type")),
        "scope_id": _normalize_text(row.get("scope_id")),
    }


def _active_policy_for_scope(
    *,
    tenant_id: str,
    scope_type: str,
    scope_id: str,
    exclude_policy_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    storage = get_storage_backend()
    params: List[Any] = [tenant_id, scope_type, scope_id]
    query = [
        """
        SELECT tenant_id, policy_id, version, status, policy_hash, policy_json, scope_type, scope_id
        FROM policy_registry_entries
        WHERE tenant_id = ?
          AND scope_type = ?
          AND scope_id = ?
          AND status = 'ACTIVE'
        """
    ]
    if exclude_policy_id:
        query.append("AND policy_id <> ?")
        params.append(exclude_policy_id)
    query.append("ORDER BY activated_at DESC, created_at DESC")
    query.append("LIMIT 1")
    row = storage.fetchone("\n".join(query), tuple(params))
    if not row:
        return None
    return {
        "tenant_id": row.get("tenant_id"),
        "policy_id": row.get("policy_id"),
        "version": int(row.get("version") or 0),
        "status": _normalize_text(row.get("status")),
        "policy_hash": _normalize_text(row.get("policy_hash")),
        "policy_json": _parse_json(row.get("policy_json"), {}),
        "scope_type": _normalize_text(row.get("scope_type")),
        "scope_id": _normalize_text(row.get("scope_id")),
    }


def _resolve_policy_ref(
    *,
    tenant_id: str,
    policy_id: Optional[str],
    policy_version: Optional[int],
    policy_json: Optional[Dict[str, Any]],
    required: bool,
    label: str,
) -> Optional[Dict[str, Any]]:
    if isinstance(policy_json, dict) and policy_json:
        normalized = json.loads(canonical_json(policy_json))
        return {
            "policy_id": _normalize_text(policy_id) or f"{label}-explicit",
            "version": int(policy_version or 0) if policy_version is not None else None,
            "status": "EXPLICIT",
            "policy_hash": sha256_json(normalized),
            "policy_json": normalized,
            "scope_type": "",
            "scope_id": "",
            "source": "explicit",
        }

    ref_id = _normalize_text(policy_id)
    if not ref_id:
        if required:
            raise ValueError(f"{label}_policy_id or {label}_policy_json is required")
        return None

    selected: Optional[Dict[str, Any]]
    source: str
    if policy_version is not None:
        selected = _policy_by_id_and_version(
            tenant_id=tenant_id,
            policy_id=ref_id,
            version=int(policy_version),
        )
        source = "registry_version"
    else:
        selected = get_registry_policy(tenant_id=tenant_id, policy_id=ref_id)
        source = "registry_latest"
    if not selected:
        if required:
            raise ValueError(f"{label} policy not found")
        return None
    policy_payload = selected.get("policy_json") if isinstance(selected.get("policy_json"), dict) else {}
    normalized = json.loads(canonical_json(policy_payload))
    return {
        **selected,
        "policy_hash": _normalize_text(selected.get("policy_hash")) or sha256_json(normalized),
        "policy_json": normalized,
        "source": source,
    }


def _extract_min_approvals(policy_json: Dict[str, Any]) -> int:
    approvals_cfg = policy_json.get("approval_requirements") if isinstance(policy_json.get("approval_requirements"), dict) else {}
    if isinstance(approvals_cfg.get("min_approvals"), (int, float)):
        return int(approvals_cfg.get("min_approvals") or 0)
    if isinstance(policy_json.get("required_approvals"), (int, float)):
        return int(policy_json.get("required_approvals") or 0)
    return 0


def _extract_required_roles(policy_json: Dict[str, Any]) -> Set[str]:
    roles: Set[str] = set()
    approvals_cfg = policy_json.get("approval_requirements") if isinstance(policy_json.get("approval_requirements"), dict) else {}
    required_roles = approvals_cfg.get("required_roles")
    if isinstance(required_roles, list):
        roles.update({_normalize_lower(item) for item in required_roles if _normalize_text(item)})
    root_roles = policy_json.get("required_roles")
    if isinstance(root_roles, list):
        roles.update({_normalize_lower(item) for item in root_roles if _normalize_text(item)})
    return roles


def _extract_protected_statuses(policy_json: Dict[str, Any]) -> Set[str]:
    raw = policy_json.get("protected_statuses")
    if not isinstance(raw, list):
        return set()
    return {_normalize_lower(item) for item in raw if _normalize_text(item)}


def _extract_risk_thresholds(payload: Any, prefix: str = "", in_risk_context: bool = False) -> Dict[str, float]:
    found: Dict[str, float] = {}
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = _normalize_text(key)
            if not key_text:
                continue
            path = f"{prefix}.{key_text}" if prefix else key_text
            lower = key_text.lower()
            path_lower = path.lower()
            risk_context = in_risk_context or ("risk" in lower) or ("risk" in path_lower)
            if isinstance(value, (int, float)) and "risk" in lower and any(
                token in lower for token in ("threshold", "limit", "max", "min", "score")
            ):
                found[path] = float(value)
            elif isinstance(value, (int, float)) and risk_context and any(
                token in lower for token in ("threshold", "limit", "max", "min", "score")
            ):
                found[path] = float(value)
            found.update(_extract_risk_thresholds(value, prefix=path, in_risk_context=risk_context))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            path = f"{prefix}[{index}]"
            found.update(_extract_risk_thresholds(item, prefix=path, in_risk_context=in_risk_context))
    return found


def _rule_key(rule: Dict[str, Any], index: int) -> str:
    explicit = _normalize_text(rule.get("rule_id") or rule.get("id"))
    if explicit:
        return explicit
    return "|".join(
        [
            _normalize_text(rule.get("transition_id")) or "*",
            _normalize_text(rule.get("project_id")) or "*",
            _normalize_text(rule.get("workflow_id")) or "*",
            _normalize_text(rule.get("environment")) or "*",
            _normalize_text(rule.get("priority")) or "1000",
            str(index),
        ]
    )


def _normalize_rule_result(rule: Dict[str, Any]) -> str:
    result = _normalize_lower(rule.get("result") or rule.get("enforcement"))
    if result in {"block", "blocked", "deny", "denied"}:
        return "BLOCK"
    if result in {"warn", "conditional"}:
        return "WARN"
    return "ALLOW"


def _transition_rules(policy_json: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rules = policy_json.get("transition_rules")
    if not isinstance(rules, list):
        return {}
    normalized: Dict[str, Dict[str, Any]] = {}
    for index, item in enumerate(rules):
        if not isinstance(item, dict):
            continue
        normalized[_rule_key(item, index)] = json.loads(canonical_json(item))
    return normalized


def build_policy_impact_diff(
    *,
    tenant_id: Optional[str],
    current_policy_id: Optional[str],
    current_policy_version: Optional[int],
    current_policy_json: Optional[Dict[str, Any]],
    candidate_policy_id: Optional[str],
    candidate_policy_version: Optional[int],
    candidate_policy_json: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    init_db()
    effective_tenant = resolve_tenant_id(tenant_id)

    candidate = _resolve_policy_ref(
        tenant_id=effective_tenant,
        policy_id=candidate_policy_id,
        policy_version=candidate_policy_version,
        policy_json=candidate_policy_json,
        required=True,
        label="candidate",
    )
    assert candidate is not None

    current = _resolve_policy_ref(
        tenant_id=effective_tenant,
        policy_id=current_policy_id,
        policy_version=current_policy_version,
        policy_json=current_policy_json,
        required=False,
        label="current",
    )
    if current is None:
        scope_type = _normalize_text(candidate.get("scope_type"))
        scope_id = _normalize_text(candidate.get("scope_id"))
        if scope_type and scope_id:
            current = _active_policy_for_scope(
                tenant_id=effective_tenant,
                scope_type=scope_type,
                scope_id=scope_id,
                exclude_policy_id=_normalize_text(candidate.get("policy_id")) or None,
            )

    current_json = current.get("policy_json") if isinstance((current or {}).get("policy_json"), dict) else {}
    candidate_json = candidate.get("policy_json") if isinstance(candidate.get("policy_json"), dict) else {}

    warnings: List[Dict[str, Any]] = []
    strengthening_signals: List[Dict[str, Any]] = []

    current_strict = bool(current_json.get("strict_fail_closed", False))
    candidate_strict = bool(candidate_json.get("strict_fail_closed", False))
    if current_strict and not candidate_strict:
        warnings.append(
            {
                "code": "WEAKEN_STRICT_FAIL_CLOSED",
                "message": "Candidate disables strict_fail_closed.",
                "from": current_strict,
                "to": candidate_strict,
            }
        )
    elif (not current_strict) and candidate_strict:
        strengthening_signals.append(
            {
                "code": "STRENGTHEN_STRICT_FAIL_CLOSED",
                "message": "Candidate enables strict_fail_closed.",
                "from": current_strict,
                "to": candidate_strict,
            }
        )

    current_min_approvals = _extract_min_approvals(current_json)
    candidate_min_approvals = _extract_min_approvals(candidate_json)
    if candidate_min_approvals < current_min_approvals:
        warnings.append(
            {
                "code": "WEAKEN_APPROVAL_REQUIREMENT",
                "message": "Candidate lowers required approvals.",
                "from": current_min_approvals,
                "to": candidate_min_approvals,
            }
        )
    elif candidate_min_approvals > current_min_approvals:
        strengthening_signals.append(
            {
                "code": "STRENGTHEN_APPROVAL_REQUIREMENT",
                "message": "Candidate increases required approvals.",
                "from": current_min_approvals,
                "to": candidate_min_approvals,
            }
        )

    current_roles = _extract_required_roles(current_json)
    candidate_roles = _extract_required_roles(candidate_json)
    if current_roles and (candidate_roles < current_roles):
        warnings.append(
            {
                "code": "WEAKEN_REQUIRED_ROLES",
                "message": "Candidate removes required approval roles.",
                "from": sorted(current_roles),
                "to": sorted(candidate_roles),
            }
        )
    elif candidate_roles > current_roles:
        strengthening_signals.append(
            {
                "code": "STRENGTHEN_REQUIRED_ROLES",
                "message": "Candidate adds required approval roles.",
                "from": sorted(current_roles),
                "to": sorted(candidate_roles),
            }
        )

    current_protected = _extract_protected_statuses(current_json)
    candidate_protected = _extract_protected_statuses(candidate_json)
    removed_protected = sorted(current_protected - candidate_protected)
    added_protected = sorted(candidate_protected - current_protected)
    if removed_protected:
        warnings.append(
            {
                "code": "WEAKEN_PROTECTED_STATUSES",
                "message": "Candidate removes protected statuses.",
                "removed": removed_protected,
                "added": [],
            }
        )
    if added_protected:
        strengthening_signals.append(
            {
                "code": "STRENGTHEN_PROTECTED_STATUSES",
                "message": "Candidate adds protected statuses.",
                "added": added_protected,
                "removed": [],
            }
        )

    current_risk = _extract_risk_thresholds(current_json)
    candidate_risk = _extract_risk_thresholds(candidate_json)
    risk_changes: List[Dict[str, Any]] = []
    for path in sorted(set(current_risk.keys()) | set(candidate_risk.keys())):
        has_current = path in current_risk
        has_candidate = path in candidate_risk
        lower_path = path.lower()
        is_min_threshold = "min" in lower_path

        direction = "NEUTRAL"
        comparison_mode = "direct"
        current_value_raw: Optional[float] = float(current_risk[path]) if has_current else None
        candidate_value_raw: Optional[float] = float(candidate_risk[path]) if has_candidate else None

        if has_current and has_candidate:
            if candidate_value_raw == current_value_raw:
                continue
            assert current_value_raw is not None
            assert candidate_value_raw is not None
            if is_min_threshold:
                direction = "WEAKENING" if candidate_value_raw < current_value_raw else "STRENGTHENING"
            else:
                direction = "WEAKENING" if candidate_value_raw > current_value_raw else "STRENGTHENING"
        elif has_current and (not has_candidate):
            # Missing candidate threshold defaults to weakest bound:
            # min-threshold -> 0, max-threshold -> unbounded.
            comparison_mode = "missing_default"
            direction = "WEAKENING"
        elif has_candidate and (not has_current):
            # Missing current threshold defaults to weakest bound:
            # min-threshold -> 0, max-threshold -> unbounded.
            comparison_mode = "missing_default"
            direction = "STRENGTHENING"
        else:
            continue

        change_item = {
            "path": path,
            "from": current_value_raw,
            "to": candidate_value_raw,
            "direction": direction,
            "comparison_mode": comparison_mode,
        }
        risk_changes.append(change_item)
        if direction == "WEAKENING":
            warnings.append(
                {
                    "code": "WEAKEN_RISK_THRESHOLD",
                    "message": "Candidate weakens a risk threshold.",
                    **change_item,
                }
            )
        elif direction == "STRENGTHENING":
            strengthening_signals.append(
                {
                    "code": "STRENGTHEN_RISK_THRESHOLD",
                    "message": "Candidate strengthens a risk threshold.",
                    **change_item,
                }
            )

    current_rules = _transition_rules(current_json)
    candidate_rules = _transition_rules(candidate_json)
    rule_changes: List[Dict[str, Any]] = []
    for key in sorted(set(current_rules.keys()) | set(candidate_rules.keys())):
        current_rule = current_rules.get(key)
        candidate_rule = candidate_rules.get(key)
        if current_rule and not candidate_rule:
            rule_changes.append({"rule": key, "change": "REMOVED", "from": current_rule, "to": None})
            if _normalize_rule_result(current_rule) == "BLOCK":
                warnings.append(
                    {
                        "code": "WEAKEN_BLOCKING_RULE_REMOVED",
                        "message": "Candidate removes a blocking transition rule.",
                        "rule": key,
                    }
                )
            continue
        if candidate_rule and not current_rule:
            rule_changes.append({"rule": key, "change": "ADDED", "from": None, "to": candidate_rule})
            if _normalize_rule_result(candidate_rule) == "BLOCK":
                strengthening_signals.append(
                    {
                        "code": "STRENGTHEN_BLOCKING_RULE_ADDED",
                        "message": "Candidate adds a blocking transition rule.",
                        "rule": key,
                    }
                )
            continue
        if not current_rule or not candidate_rule:
            continue
        if canonical_json(current_rule) == canonical_json(candidate_rule):
            continue
        rule_changes.append({"rule": key, "change": "MODIFIED", "from": current_rule, "to": candidate_rule})
        old_result = _normalize_rule_result(current_rule)
        new_result = _normalize_rule_result(candidate_rule)
        if old_result == "BLOCK" and new_result != "BLOCK":
            warnings.append(
                {
                    "code": "WEAKEN_RULE_RESULT",
                    "message": "Candidate changes a blocking rule to a less strict result.",
                    "rule": key,
                    "from": old_result,
                    "to": new_result,
                }
            )
        elif old_result != "BLOCK" and new_result == "BLOCK":
            strengthening_signals.append(
                {
                    "code": "STRENGTHEN_RULE_RESULT",
                    "message": "Candidate changes a rule to blocking behavior.",
                    "rule": key,
                    "from": old_result,
                    "to": new_result,
                }
            )

    overall = "NEUTRAL"
    if warnings:
        overall = "WEAKENING"
    elif strengthening_signals:
        overall = "STRENGTHENING"

    report_id = str(uuid.uuid4())
    return {
        "report_id": report_id,
        "trace_id": report_id,
        "tenant_id": effective_tenant,
        "generated_at": _utc_now(),
        "overall": overall,
        "current_policy": {
            "policy_id": _normalize_text((current or {}).get("policy_id")) or None,
            "policy_version": (current or {}).get("version"),
            "policy_hash": _normalize_text((current or {}).get("policy_hash")) or (sha256_json(current_json) if current_json else None),
            "source": (current or {}).get("source") if current else None,
        },
        "candidate_policy": {
            "policy_id": _normalize_text(candidate.get("policy_id")) or None,
            "policy_version": candidate.get("version"),
            "policy_hash": _normalize_text(candidate.get("policy_hash")) or sha256_json(candidate_json),
            "source": candidate.get("source"),
        },
        "strictness_delta": {
            "strict_fail_closed": {"from": current_strict, "to": candidate_strict},
            "approvals_required": {"from": current_min_approvals, "to": candidate_min_approvals},
            "required_roles": {"from": sorted(current_roles), "to": sorted(candidate_roles)},
            "protected_statuses": {"removed": removed_protected, "added": added_protected},
            "risk_threshold_changes": risk_changes,
        },
        "rule_changes": rule_changes,
        "warnings": warnings,
        "strengthening_signals": strengthening_signals,
        "summary": {
            "warning_count": len(warnings),
            "strengthening_count": len(strengthening_signals),
            "rule_change_count": len(rule_changes),
            "risk_threshold_change_count": len(risk_changes),
        },
    }
