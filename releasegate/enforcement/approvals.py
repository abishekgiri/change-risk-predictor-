"""
Approval Enforcement Control (SEC-PR-004).

Ensures PRs have required approvals from appropriate reviewers.
"""
from typing import Dict, Any, List, Optional, Sequence, Set
from .types import ControlBase, ControlContext, ControlSignalSet, Finding
from releasegate.signals.approvals.types import Review, ApprovalRequirement
from releasegate.signals.approvals.validator import validate_approvals
from releasegate.signals.approvals.evidence import approvals_to_findings
from releasegate.signals.approvals.evaluator import (
    evaluate_role_aware_approvals,
    normalize_approval_policy,
    parse_codeowners,
)

class ApprovalsControl(ControlBase):
    """
    Approval enforcement control.
    
    Validates that PRs have required approvals:
    - Counts valid (non-stale, APPROVED) reviews
    - Checks reviewer roles (security, manager, etc.)
    - Detects stale approvals (submitted before latest commit)
    """
    
    def execute(self, ctx: ControlContext) -> ControlSignalSet:
        """
        Execute approval validation.
        
        Args:
            ctx: Control execution context
        
        Returns:
            Control signals and findings
        """
        approvals_cfg = ctx.config.get("approvals") if isinstance(ctx.config.get("approvals"), dict) else None
        if approvals_cfg is not None:
            return self._execute_role_aware(ctx, approvals_cfg)

        return self._execute_legacy(ctx)

    def _execute_legacy(self, ctx: ControlContext) -> ControlSignalSet:
        # Legacy approval requirements from config
        approval_config = ctx.config.get("approval_requirements", [])
        requirements = [
            ApprovalRequirement(role=req["role"], count=req["count"])
            for req in approval_config
            if isinstance(req, dict) and "role" in req and "count" in req
        ]

        # If no requirements configured, pass by default
        if not requirements:
            return ControlSignalSet(
                signals={
                    "approvals.required": False,
                    "approvals.satisfied": True
                },
                findings=[]
            )
        
        # Fetch reviews from provider
        reviews = self._fetch_reviews(ctx)
        if reviews is None:
            # Fail-open if we can't fetch approvals data
            return ControlSignalSet(
                signals={
                    "approvals.required": False,
                    "approvals.satisfied": True,
                    "approvals.skipped": True,
                    "approvals.data_available": False
                },
                findings=[]
            )
        
        # Validate approvals
        approval_findings = validate_approvals(
            reviews=reviews,
            requirements=requirements,
            head_sha=ctx.config.get("head_sha", ""),
            config=ctx.config
        )
        
        # Convert to universal Finding format
        findings = approvals_to_findings(approval_findings)
        
        # Generate signals
        all_satisfied = all(af.satisfied for af in approval_findings)
        unsatisfied_count = sum(1 for af in approval_findings if not af.satisfied)
        
        signals: Dict[str, Any] = {
            "approvals.required": True,
            "approvals.satisfied": all_satisfied,
            "approvals.unsatisfied_count": unsatisfied_count,
            "approvals.total_requirements": len(requirements),
            "approvals.data_available": True,
        }
        
        # Add per-role signals
        for af in approval_findings:
            role = af.requirement.role
            signals[f"approvals.{role}.satisfied"] = af.satisfied
            signals[f"approvals.{role}.count"] = af.actual_count
            signals[f"approvals.{role}.required"] = af.requirement.count
        
        return ControlSignalSet(
            signals=signals,
            findings=findings
        )

    def _execute_role_aware(self, ctx: ControlContext, approvals_cfg: Dict[str, Any]) -> ControlSignalSet:
        policy = normalize_approval_policy(approvals_cfg)
        needs_approval = bool(
            policy.min_total > 0
            or policy.require_codeowner
            or policy.require_security_team
        )
        if not needs_approval:
            return ControlSignalSet(
                signals={
                    "approvals.required": False,
                    "approvals.satisfied": True,
                    "approvals": {
                        "min_total_required": policy.min_total,
                        "total_approvals": 0,
                        "disallow_self_approval": policy.disallow_self_approval,
                        "self_approval_detected": False,
                        "codeowner_required": policy.require_codeowner,
                        "codeowner_approved": None,
                        "security_team_required": policy.require_security_team,
                        "security_team_approved": None,
                        "approved_by": [],
                        "reason_codes": [],
                    },
                },
                findings=[],
            )

        reviews = self._fetch_reviews(ctx)
        if reviews is None:
            return ControlSignalSet(
                signals={
                    "approvals.required": False,
                    "approvals.satisfied": True,
                    "approvals.skipped": True,
                    "approvals.data_available": False
                },
                findings=[],
            )

        pr_author = self._resolve_pr_author(ctx)
        codeowner_users, codeowner_teams = self._resolve_codeowners(ctx, approvals_cfg)
        team_members = self._resolve_team_members(ctx, approvals_cfg, list(codeowner_teams) + policy.security_team_slugs)

        result = evaluate_role_aware_approvals(
            reviews=reviews,
            policy=policy,
            head_sha=str(ctx.config.get("head_sha", "") or ""),
            pr_author=pr_author,
            codeowner_users=codeowner_users,
            codeowner_teams=codeowner_teams,
            team_members_by_slug=team_members,
        )

        structured = {
            "min_total_required": result.min_total_required,
            "total_approvals": result.total_approvals,
            "disallow_self_approval": result.disallow_self_approval,
            "self_approval_detected": result.self_approval_detected,
            "codeowner_required": result.codeowner_required,
            "codeowner_approved": result.codeowner_approved,
            "security_team_required": result.security_team_required,
            "security_team_approved": result.security_team_approved,
            "approved_by": list(result.approved_by),
            "reason_codes": list(result.reason_codes),
        }

        signals: Dict[str, Any] = {
            "approvals.required": True,
            "approvals.satisfied": len(result.reason_codes) == 0,
            "approvals.unsatisfied_count": len(result.reason_codes),
            "approvals.total_requirements": (
                1
                + (1 if result.codeowner_required else 0)
                + (1 if result.security_team_required else 0)
            ),
            "approvals.data_available": True,
            "approvals.reason_codes": list(result.reason_codes),
            "approvals.count": result.total_approvals,
            "approvals.security_review": result.security_approvals_count,
            "approvals": structured,
        }

        findings: List[Finding] = []
        for code in result.reason_codes:
            findings.append(
                Finding(
                    control_id="SEC-PR-004",
                    rule_id=code,
                    severity="HIGH",
                    message=self._reason_message(code, structured),
                    context={"approvals": structured},
                )
            )

        return ControlSignalSet(signals=signals, findings=findings)

    def _fetch_reviews(self, ctx: ControlContext) -> Optional[List[Review]]:
        """
        Fetch PR reviews from the provider.
        
        Args:
            ctx: Control execution context
        
        Returns:
            List of Review objects
        """
        if ctx.provider is None:
            # No provider (testing mode), signal skip
            return None
        
        try:
            # Fetch reviews from GitHub/GitLab
            get_reviews = getattr(ctx.provider, "get_reviews", None)
            if not callable(get_reviews):
                return None
            return get_reviews(ctx.repo, ctx.pr_number)
        except Exception as e:
            return None

    def _resolve_pr_author(self, ctx: ControlContext) -> Optional[str]:
        author = str(ctx.config.get("pr_author") or "").strip()
        if author:
            return author

        if isinstance(ctx.diff, dict):
            for key in ("author", "author_login", "pr_author"):
                val = str(ctx.diff.get(key) or "").strip()
                if val:
                    return val

        if ctx.provider is None:
            return None
        try:
            get_pr_author = getattr(ctx.provider, "get_pr_author", None)
            if callable(get_pr_author):
                val = get_pr_author(ctx.repo, ctx.pr_number)
                val = str(val or "").strip()
                if val:
                    return val
        except Exception:
            return None
        return None

    def _resolve_codeowners(self, ctx: ControlContext, approvals_cfg: Dict[str, Any]) -> tuple[Set[str], Set[str]]:
        users: Set[str] = set()
        teams: Set[str] = set()

        configured = approvals_cfg.get("codeowners")
        if isinstance(configured, list):
            for item in configured:
                raw = str(item or "").strip()
                if not raw:
                    continue
                raw = raw[1:] if raw.startswith("@") else raw
                if "/" in raw:
                    teams.add(raw)
                    teams.add(raw.split("/", 1)[-1])
                else:
                    users.add(raw)
            return users, teams

        codeowners_text = str(ctx.config.get("codeowners_content") or "")
        if not codeowners_text and ctx.provider is not None:
            for path in (".github/CODEOWNERS", "CODEOWNERS"):
                try:
                    get_file_content = getattr(ctx.provider, "get_file_content", None)
                    if not callable(get_file_content):
                        break
                    text = get_file_content(ctx.repo, path, ref=ctx.config.get("head_sha"))
                    if text:
                        codeowners_text = str(text)
                        break
                except Exception:
                    continue

        if codeowners_text:
            parsed_users, parsed_teams = parse_codeowners(codeowners_text)
            users.update(parsed_users)
            teams.update(parsed_teams)
        return users, teams

    def _resolve_team_members(
        self,
        ctx: ControlContext,
        approvals_cfg: Dict[str, Any],
        slugs: Sequence[str],
    ) -> Dict[str, List[str]]:
        members: Dict[str, List[str]] = {}
        configured = approvals_cfg.get("team_members")
        if isinstance(configured, dict):
            for slug, usernames in configured.items():
                if isinstance(usernames, list):
                    cleaned = [str(u).strip() for u in usernames if str(u).strip()]
                    if cleaned:
                        members[str(slug)] = cleaned

        fallback_config = ctx.config.get("security_team_members")
        if isinstance(fallback_config, dict):
            for slug, usernames in fallback_config.items():
                if isinstance(usernames, list):
                    cleaned = [str(u).strip() for u in usernames if str(u).strip()]
                    if cleaned and str(slug) not in members:
                        members[str(slug)] = cleaned

        if ctx.provider is not None:
            get_team_members = getattr(ctx.provider, "get_team_members", None)
            if callable(get_team_members):
                for slug in slugs:
                    candidate = str(slug or "").strip()
                    if not candidate:
                        continue
                    # Skip fetch if we already have a configured map.
                    if candidate in members:
                        continue
                    try:
                        fetched = get_team_members(candidate)
                    except Exception:
                        fetched = None
                    if isinstance(fetched, list):
                        cleaned = [str(u).strip() for u in fetched if str(u).strip()]
                        if cleaned:
                            members[candidate] = cleaned
        return members

    def _reason_message(self, reason_code: str, approvals: Dict[str, Any]) -> str:
        messages = {
            "APPROVALS_INSUFFICIENT": (
                f"Approvals insufficient: {approvals.get('total_approvals', 0)} "
                f"of {approvals.get('min_total_required', 0)} required."
            ),
            "SELF_APPROVAL_NOT_ALLOWED": "PR author approval does not satisfy approval policy.",
            "CODEOWNER_APPROVAL_REQUIRED": "At least one CODEOWNER approval is required.",
            "SECURITY_APPROVAL_REQUIRED": "At least one security team approval is required.",
        }
        return messages.get(reason_code, reason_code)
