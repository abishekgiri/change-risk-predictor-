"""GitHub PR check integration for the Cross-System Governance Fabric.

When a PR is opened or updated, CI calls POST /fabric/github/pr-check.
This module evaluates the PR against all active fabric rules and posts a
real commit status back to GitHub so the PR cannot merge without a
governance-clean signal.

Commit status mapping
---------------------
PASS  (all rules satisfied)          → state=success
WARN  (violations but AUDIT mode)    → state=success  (non-blocking, informational)
                                        description prefixed "AUDIT: …" so the
                                        green checkmark is not misleading.
BLOCK (violations in STRICT mode)    → state=failure
ERROR (fabric engine/DB error)       → state=error

Comments are upserted with a hidden marker so CI retries don't spam the PR.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from releasegate.integrations.github import (
    COMMENT_FAILED,
    COMMENT_POSTED,
    COMMENT_SKIPPED,
    COMMENT_UPDATED,
    set_commit_status,
    upsert_pr_comment,
)
from releasegate.fabric.missing_links import evaluate_missing_links, should_block

log = logging.getLogger(__name__)

# Status context posted to GitHub
GITHUB_STATUS_CONTEXT = "releasegate/fabric"

# Hidden marker embedded in PR comments so retries update the same comment
# instead of appending a new one. Keep stable — changing breaks idempotency.
_PR_COMMENT_MARKER = "<!-- releasegate-fabric:pr-check -->"


def _format_violations(violations: List[Dict[str, str]], *, prefix: str = "") -> str:
    """Format violation list for a GitHub commit status description (≤140 chars)."""
    if not violations:
        return "All governance rules satisfied."
    codes = ", ".join(v["code"] for v in violations)
    return f"{prefix}{len(violations)} violation(s): {codes}"[:140]


def _build_pr_comment(
    *,
    violations: List[Dict[str, str]],
    enforcement_mode: str,
    tenant_id: str,
    change_id: Optional[str],
    sha: Optional[str] = None,
) -> str:
    """Build a markdown comment for the PR. Always includes the idempotency marker."""
    if not violations:
        return (
            f"{_PR_COMMENT_MARKER}\n"
            "## ReleaseGate Fabric ✅\n\n"
            "All governance rules satisfied. This change is fully linked across systems."
            + (f"\n\n<sub>Commit: `{sha[:7]}`</sub>" if sha else "")
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
    sha_line = f"\n\n<sub>Commit: `{sha[:7]}`</sub>" if sha else ""

    return (
        f"{_PR_COMMENT_MARKER}\n"
        f"## ReleaseGate Fabric {'🚫' if blocked else '⚠️'}\n\n"
        f"{status_line}\n\n"
        f"| Violation | Details |\n"
        f"|-----------|----------|\n"
        f"{rows}\n\n"
        f"**Change record:** {change_ref}  \n"
        f"**Tenant:** `{tenant_id}`\n\n"
        f"Resolve each violation and re-push to re-evaluate."
        f"{sha_line}"
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

    Returns
    -------
    {
        "verdict":          "PASS" | "WARN" | "BLOCK" | "ERROR",
        "violations":       [...],
        "github_status_ok": bool,
        "comment_status":   "posted" | "updated" | "skipped" | "failed",
    }
    """
    # 1. Evaluate missing-link rules
    try:
        violations = evaluate_missing_links(
            record=record,
            policy_overrides=policy_overrides,
        )
    except Exception as exc:
        log.exception("Fabric rule evaluation failed for repo=%s pr=%s", repo, pr_number)
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
            "comment_status": COMMENT_SKIPPED,
            "error": str(exc),
        }

    # 2. Determine verdict + GitHub state
    if not violations:
        verdict = "PASS"
        gh_state = "success"
        description = _format_violations(violations)
    elif should_block(violations=violations, enforcement_mode=enforcement_mode):
        verdict = "BLOCK"
        gh_state = "failure"
        description = _format_violations(violations)
    else:
        verdict = "WARN"
        gh_state = "success"  # audit-only → non-blocking
        # Prefix description so the green checkmark is not misleading — the
        # reader sees "AUDIT: 3 violations" instead of an unqualified green state.
        description = _format_violations(violations, prefix="AUDIT: ")

    # 3. Post commit status
    status_ok = set_commit_status(
        repo_name=repo,
        sha=sha,
        state=gh_state,
        description=description,
        context=GITHUB_STATUS_CONTEXT,
        target_url=target_url,
    )

    # 4. Upsert PR comment (only when violations present or a new PASS record).
    comment_status = COMMENT_SKIPPED
    if post_pr_comment and (violations or verdict == "PASS"):
        comment_body = _build_pr_comment(
            violations=violations,
            enforcement_mode=enforcement_mode,
            tenant_id=tenant_id,
            change_id=change_id,
            sha=sha,
        )
        comment_status = upsert_pr_comment(
            repo_name=repo,
            pr_number=pr_number,
            body=comment_body,
            marker=_PR_COMMENT_MARKER,
        )
        if comment_status == COMMENT_FAILED:
            log.warning(
                "Fabric PR comment upsert failed for repo=%s pr=%s sha=%s",
                repo, pr_number, sha,
            )

    return {
        "verdict": verdict,
        "violations": violations,
        "github_status_ok": status_ok,
        "comment_status": comment_status,
        # Back-compat bool; True only when we actually posted or updated a comment.
        "comment_ok": comment_status in (COMMENT_POSTED, COMMENT_UPDATED),
    }
