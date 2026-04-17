"""GitHub PR check integration for the Cross-System Governance Fabric.

When a PR is opened or updated, CI calls POST /fabric/github/pr-check.
This module evaluates the PR against all active fabric rules and posts a
real commit status back to GitHub so the PR cannot merge without a
governance-clean signal.

Commit status mapping
---------------------
PASS  (all rules satisfied)          → state=success
WARN  (violations but AUDIT mode)    → state=success  (non-blocking, informational)
BLOCK (violations in STRICT mode)    → state=failure
ERROR (fabric engine/DB error)       → state=error
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from releasegate.integrations.github import post_comment, set_commit_status
from releasegate.fabric.missing_links import evaluate_missing_links, should_block

# Status context posted to GitHub
GITHUB_STATUS_CONTEXT = "releasegate/fabric"


def _format_violations(violations: List[Dict[str, str]]) -> str:
    """Format violation list for a GitHub commit status description (≤140 chars)."""
    if not violations:
        return "All governance rules satisfied."
    codes = ", ".join(v["code"] for v in violations)
    return f"{len(violations)} violation(s): {codes}"[:140]


def _build_pr_comment(
    *,
    violations: List[Dict[str, str]],
    enforcement_mode: str,
    tenant_id: str,
    change_id: Optional[str],
) -> str:
    """Build a markdown comment for the PR when violations are found."""
    if not violations:
        return (
            "## ReleaseGate Fabric ✅\n\n"
            "All governance rules satisfied. This change is fully linked across systems."
        )

    blocked = should_block(violations=violations, enforcement_mode=enforcement_mode)
    status_line = (
        "**BLOCKED** — this PR cannot merge until violations are resolved."
        if blocked
        else "**AUDIT** — violations logged but merge is not blocked (audit-only mode)."
    )

    rows = "\n".join(
        f"| `{v['code']}` | {v['message']} |"
        for v in violations
    )

    change_ref = f"`{change_id}`" if change_id else "_(no change record yet)_"

    return (
        f"## ReleaseGate Fabric {'🚫' if blocked else '⚠️'}\n\n"
        f"{status_line}\n\n"
        f"| Violation | Details |\n"
        f"|-----------|----------|\n"
        f"{rows}\n\n"
        f"**Change record:** {change_ref}  \n"
        f"**Tenant:** `{tenant_id}`\n\n"
        f"Resolve each violation and re-push to re-evaluate."
    )


def evaluate_and_enforce_pr_check(
    *,
    repo: str,
    sha: str,
    pr_number: int,
    tenant_id: str,
    record: Dict[str, Any],
    enforcement_mode: str = "STRICT",
    policy_overrides: Optional[Dict[str, Any]] = None,
    change_id: Optional[str] = None,
    target_url: Optional[str] = None,
    post_pr_comment: bool = True,
) -> Dict[str, Any]:
    """Evaluate a PR record against fabric rules and post status to GitHub.

    Parameters
    ----------
    repo:              GitHub repo in ``owner/repo`` format.
    sha:               Full commit SHA for the head of the PR.
    pr_number:         PR number (used for comment posting).
    tenant_id:         ReleaseGate tenant.
    record:            Dict of link fields (jira_issue_key, pr_repo, deploy_id, …).
                       Typically the materialized ChangeRecord view.
    enforcement_mode:  "STRICT" (block) or "AUDIT" (log-only).
    policy_overrides:  Per-tenant rule overrides passed to evaluate_missing_links.
    change_id:         Optional change_id for the commit status target URL / comment.
    target_url:        Optional URL to surface in the GitHub commit status detail link.
    post_pr_comment:   Whether to post a comment on the PR (default True).

    Returns
    -------
    {
        "verdict":         "PASS" | "WARN" | "BLOCK",
        "violations":      [...],
        "github_status_ok": bool,   # True if commit status API call succeeded
        "comment_ok":       bool,   # True if comment was posted (or skipped)
    }
    """
    # 1. Evaluate missing-link rules
    try:
        violations = evaluate_missing_links(
            record=record,
            policy_overrides=policy_overrides,
        )
    except Exception as exc:
        # Engine error → post error status and return early
        set_commit_status(
            repo_name=repo,
            sha=sha,
            state="error",
            description=f"ReleaseGate fabric engine error: {exc}"[:140],
            context=GITHUB_STATUS_CONTEXT,
            target_url=target_url,
        )
        return {
            "verdict": "ERROR",
            "violations": [],
            "github_status_ok": False,
            "comment_ok": False,
            "error": str(exc),
        }

    # 2. Determine verdict + GitHub state
    if not violations:
        verdict = "PASS"
        gh_state = "success"
    elif should_block(violations=violations, enforcement_mode=enforcement_mode):
        verdict = "BLOCK"
        gh_state = "failure"
    else:
        verdict = "WARN"
        gh_state = "success"  # audit-only → non-blocking

    description = _format_violations(violations)

    # 3. Post commit status
    status_ok = set_commit_status(
        repo_name=repo,
        sha=sha,
        state=gh_state,
        description=description,
        context=GITHUB_STATUS_CONTEXT,
        target_url=target_url,
    )

    # 4. Post PR comment if there are violations (or always on BLOCK)
    comment_ok = True
    if post_pr_comment and (violations or verdict == "PASS"):
        try:
            comment_body = _build_pr_comment(
                violations=violations,
                enforcement_mode=enforcement_mode,
                tenant_id=tenant_id,
                change_id=change_id,
            )
            post_comment(repo_name=repo, pr_number=pr_number, body=comment_body)
        except Exception:
            comment_ok = False

    return {
        "verdict": verdict,
        "violations": violations,
        "github_status_ok": status_ok,
        "comment_ok": comment_ok,
    }
