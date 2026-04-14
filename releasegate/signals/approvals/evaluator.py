"""
Role-aware approval evaluator.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .types import Review, RoleAwareApprovalPolicy, RoleAwareApprovalResult
from .validator import is_review_stale


def parse_codeowners(content: str) -> Tuple[Set[str], Set[str]]:
    """
    Parse CODEOWNERS content and return (usernames, team_slugs).
    """
    users: Set[str] = set()
    teams: Set[str] = set()
    if not isinstance(content, str):
        return users, teams

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue
        for owner in parts[1:]:
            if not owner.startswith("@"):
                continue
            token = owner[1:].strip()
            if not token:
                continue
            if "/" in token:
                teams.add(token)
                teams.add(token.split("/", 1)[-1])
            else:
                users.add(token)
    return users, teams


def normalize_approval_policy(raw: Optional[Dict[str, Any]]) -> RoleAwareApprovalPolicy:
    cfg = raw if isinstance(raw, dict) else {}
    min_total = int(cfg.get("min_total", 1))
    if min_total < 0:
        min_total = 0
    max_age_raw = cfg.get("max_age_seconds")
    max_age_seconds: Optional[int] = None
    if max_age_raw is not None:
        try:
            parsed = int(max_age_raw)
            if parsed > 0:
                max_age_seconds = parsed
        except Exception:
            max_age_seconds = None

    slugs = cfg.get("security_team_slugs", [])
    if not isinstance(slugs, list):
        slugs = []

    return RoleAwareApprovalPolicy(
        min_total=min_total,
        disallow_self_approval=bool(cfg.get("disallow_self_approval", True)),
        require_codeowner=bool(cfg.get("require_codeowner", False)),
        require_security_team=bool(cfg.get("require_security_team", False)),
        security_team_slugs=[str(s).strip() for s in slugs if str(s).strip()],
        max_age_seconds=max_age_seconds,
    )


def _dt(value: Optional[datetime]) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)


def _is_review_expired(
    review: Review,
    *,
    max_age_seconds: Optional[int],
    evaluation_time: datetime,
) -> bool:
    if max_age_seconds is None or max_age_seconds <= 0:
        return False
    submitted_at = _dt(review.submitted_at)
    age_seconds = max(0.0, (evaluation_time - submitted_at).total_seconds())
    return age_seconds > float(max_age_seconds)


def _latest_reviews_by_user(reviews: Sequence[Review]) -> Dict[str, Review]:
    latest: Dict[str, Review] = {}
    for review in reviews:
        reviewer = str(review.reviewer or "").strip()
        if not reviewer:
            continue
        # Ignore bot approvals in v1 to avoid machine user bypasses.
        if reviewer.lower().endswith("[bot]"):
            continue
        existing = latest.get(reviewer)
        if existing is None or _dt(review.submitted_at) >= _dt(existing.submitted_at):
            latest[reviewer] = review
    return latest


def _expand_team_members(
    slugs: Iterable[str],
    team_members_by_slug: Optional[Dict[str, Sequence[str]]],
) -> Set[str]:
    members: Set[str] = set()
    mapping = team_members_by_slug if isinstance(team_members_by_slug, dict) else {}
    for raw_slug in slugs:
        slug = str(raw_slug or "").strip()
        if not slug:
            continue
        candidates = {
            slug,
            slug.lower(),
            slug.split("/", 1)[-1],
            slug.split("/", 1)[-1].lower(),
        }
        for candidate in candidates:
            value = mapping.get(candidate)
            if isinstance(value, (list, tuple, set)):
                members.update(str(v).strip() for v in value if str(v).strip())
    return members


def evaluate_role_aware_approvals(
    *,
    reviews: Sequence[Review],
    policy: RoleAwareApprovalPolicy,
    head_sha: str,
    pr_author: Optional[str],
    codeowner_users: Optional[Set[str]] = None,
    codeowner_teams: Optional[Set[str]] = None,
    team_members_by_slug: Optional[Dict[str, Sequence[str]]] = None,
    evaluation_time: Optional[datetime] = None,
) -> RoleAwareApprovalResult:
    evaluated_at = _dt(evaluation_time) if evaluation_time is not None else datetime.now(timezone.utc)
    latest = _latest_reviews_by_user(reviews)

    approved_fresh: Set[str] = set()
    stale_reviewers: Set[str] = set()
    expired_reviewers: Set[str] = set()
    for reviewer, review in latest.items():
        if str(review.state or "").upper() != "APPROVED":
            continue
        if is_review_stale(review, head_sha):
            stale_reviewers.add(reviewer)
            continue
        if _is_review_expired(
            review,
            max_age_seconds=policy.max_age_seconds,
            evaluation_time=evaluated_at,
        ):
            expired_reviewers.add(reviewer)
            continue
        approved_fresh.add(reviewer)

    author = str(pr_author or "").strip()
    self_approval_detected = bool(author and author in approved_fresh)

    counted = set(approved_fresh)
    if policy.disallow_self_approval and author:
        counted.discard(author)

    codeowner_required = bool(policy.require_codeowner)
    security_required = bool(policy.require_security_team)

    codeowner_members: Set[str] = set(codeowner_users or set())
    if codeowner_teams:
        codeowner_members.update(_expand_team_members(codeowner_teams, team_members_by_slug))
    codeowner_approved: Optional[bool] = None
    if codeowner_required:
        codeowner_approved = any(user in counted for user in codeowner_members)

    security_members = _expand_team_members(policy.security_team_slugs, team_members_by_slug)
    security_approved: Optional[bool] = None
    security_approvals_count = 0
    if security_required:
        security_approved_by = sorted([u for u in counted if u in security_members])
        security_approvals_count = len(security_approved_by)
        security_approved = security_approvals_count > 0

    reason_codes: List[str] = []
    if len(counted) < policy.min_total:
        reason_codes.append("APPROVALS_INSUFFICIENT")
        if policy.disallow_self_approval and self_approval_detected:
            reason_codes.append("SELF_APPROVAL_NOT_ALLOWED")
        if expired_reviewers:
            reason_codes.append("APPROVALS_EXPIRED")
    if codeowner_required and not codeowner_approved:
        reason_codes.append("CODEOWNER_APPROVAL_REQUIRED")
    if security_required and not security_approved:
        reason_codes.append("SECURITY_APPROVAL_REQUIRED")

    return RoleAwareApprovalResult(
        min_total_required=policy.min_total,
        total_approvals=len(counted),
        disallow_self_approval=policy.disallow_self_approval,
        self_approval_detected=self_approval_detected,
        codeowner_required=codeowner_required,
        codeowner_approved=codeowner_approved,
        security_team_required=security_required,
        security_team_approved=security_approved,
        approved_by=sorted(counted),
        reason_codes=reason_codes,
        security_approvals_count=security_approvals_count,
        stale_reviewers=sorted(stale_reviewers),
        expired_reviewers=sorted(expired_reviewers),
        max_age_seconds=policy.max_age_seconds,
    )
