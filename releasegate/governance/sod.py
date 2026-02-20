from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Set

from releasegate.governance.actors import build_identity_alias_map, normalize_actor_values


_DEFAULT_RULES = (
    {
        "name": "pr-author-cannot-approve-override",
        "left": "pr_author",
        "right": "override_approved_by",
        "reason_code": "SOD_PR_AUTHOR_APPROVER_CONFLICT",
        "message": "PR author cannot approve override",
    },
    {
        "name": "requester-cannot-approve-own-override",
        "left": "override_requested_by",
        "right": "override_approved_by",
        "reason_code": "SOD_REQUESTER_APPROVER_CONFLICT",
        "message": "override requestor cannot self-approve",
    },
)


def _as_principal_set(raw: Any, *, alias_map: Dict[str, str]) -> Set[str]:
    if raw is None:
        return set()
    if isinstance(raw, (set, frozenset, list, tuple)):
        return normalize_actor_values(raw, alias_map=alias_map)
    return normalize_actor_values([raw], alias_map=alias_map)


def evaluate_separation_of_duties(
    *,
    actors: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, str]]:
    cfg = config or {}
    enabled = bool(cfg.get("enabled", True))
    if not enabled:
        return None

    alias_map = build_identity_alias_map(cfg.get("identity_aliases"))
    actor_map: Dict[str, Set[str]] = {
        str(key): _as_principal_set(value, alias_map=alias_map)
        for key, value in (actors or {}).items()
    }
    rules = cfg.get("rules")
    if not isinstance(rules, Iterable) or isinstance(rules, (str, bytes)):
        rules = _DEFAULT_RULES

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        left_key = str(rule.get("left") or "").strip()
        right_key = str(rule.get("right") or "").strip()
        if not left_key or not right_key:
            continue
        left = actor_map.get(left_key, set())
        right = actor_map.get(right_key, set())
        if left and right and left.intersection(right):
            return {
                "rule": str(rule.get("name") or f"{left_key}!={right_key}"),
                "reason_code": str(rule.get("reason_code") or "SOD_CONFLICT"),
                "message": str(rule.get("message") or "separation-of-duties conflict"),
            }

    deny_self = bool(cfg.get("deny_self_approval", True))
    if deny_self:
        requester = actor_map.get("override_requested_by", set())
        approver = actor_map.get("override_approved_by", set())
        if requester and approver and requester.intersection(approver):
            return {
                "rule": "deny-self-approval",
                "reason_code": "SOD_REQUESTER_APPROVER_CONFLICT",
                "message": "override requestor cannot self-approve",
            }

    return None
