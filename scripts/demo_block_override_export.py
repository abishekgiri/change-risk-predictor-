#!/usr/bin/env python3
"""
Create a deterministic demo trail:
1) BLOCKED decision
2) ALLOWED override decision + immutable override ledger event
3) Export audit data to JSON + CSV
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Literal

from releasegate.audit.overrides import list_overrides, record_override, verify_override_chain
from releasegate.audit.reader import AuditReader
from releasegate.audit.recorder import AuditRecorder
from releasegate.decision.types import Decision, EnforcementTargets


def _build_decision(
    *,
    release_status: Literal["ALLOWED", "BLOCKED", "CONDITIONAL", "SKIPPED"],
    message: str,
    repo: str,
    pr_number: int,
    issue_key: str,
    evaluation_key: str,
) -> Decision:
    return Decision(
        timestamp=datetime.now(timezone.utc),
        release_status=release_status,
        context_id=f"jira-{issue_key}",
        message=message,
        policy_bundle_hash="demo-bundle",
        evaluation_key=evaluation_key,
        enforcement_targets=EnforcementTargets(
            repository=repo,
            pr_number=pr_number,
            ref="HEAD",
            external={"jira": [issue_key]},
        ),
    )


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        path.write_text("")
        return
    fieldnames: List[str] = []
    for row in rows:
        for k in row.keys():
            if k not in fieldnames:
                fieldnames.append(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate demo audit flow artifacts.")
    parser.add_argument("--repo", default="demo/service-api")
    parser.add_argument("--pr", type=int, default=184)
    parser.add_argument("--issue", default="DEMO-184")
    parser.add_argument("--transition", default="Ready for Release -> Done")
    parser.add_argument("--block-reason", default="High-risk transition requires explicit override.")
    parser.add_argument("--actor", default="release-manager@example.com")
    parser.add_argument("--reason", default="Emergency release override approved")
    parser.add_argument("--out-dir", default="audit_bundles/demo_flow")
    args = parser.parse_args()

    run_nonce = uuid.uuid4().hex
    base_eval = hashlib.sha256(
        f"{args.repo}:{args.pr}:{args.issue}:{run_nonce}".encode("utf-8")
    ).hexdigest()

    blocked_decision = _build_decision(
        release_status="BLOCKED",
        message=f"BLOCKED: {args.block_reason}",
        repo=args.repo,
        pr_number=args.pr,
        issue_key=args.issue,
        evaluation_key=f"{base_eval}:blocked",
    )
    blocked_decision = AuditRecorder.record_with_context(
        blocked_decision,
        repo=args.repo,
        pr_number=args.pr,
    )

    override_decision = _build_decision(
        release_status="ALLOWED",
        message=f"Override applied: {args.reason}",
        repo=args.repo,
        pr_number=args.pr,
        issue_key=args.issue,
        evaluation_key=f"{base_eval}:override",
    )
    override_decision = AuditRecorder.record_with_context(
        override_decision,
        repo=args.repo,
        pr_number=args.pr,
    )

    override_event = record_override(
        repo=args.repo,
        pr_number=args.pr,
        issue_key=args.issue,
        decision_id=override_decision.decision_id,
        actor=args.actor,
        reason=args.reason,
    )

    decisions = AuditReader.list_decisions(repo=args.repo, pr=args.pr, limit=100)
    overrides = list_overrides(repo=args.repo, pr=args.pr, limit=100)
    chain = verify_override_chain(repo=args.repo, pr=args.pr)

    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_repo = args.repo.replace("/", "__")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"{safe_repo}__pr_{args.pr}__{now}.json"
    csv_path = out_dir / f"{safe_repo}__pr_{args.pr}__{now}.csv"

    payload = {
        "repo": args.repo,
        "pr_number": args.pr,
        "issue_key": args.issue,
        "blocked_decision_id": blocked_decision.decision_id,
        "override_decision_id": override_decision.decision_id,
        "override_event_id": override_event.get("override_id"),
        "override_chain": chain,
        "decisions": decisions,
        "overrides": overrides,
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    csv_rows: List[Dict[str, Any]] = []
    for d in decisions:
        csv_rows.append({"record_type": "decision", **d})
    for o in overrides:
        csv_rows.append({"record_type": "override", **o})
    _write_csv(csv_path, csv_rows)

    print("ReleaseGate Demo Complete")
    print(f"Jira issue key: {args.issue}")
    print(f"Transition attempted: {args.transition}")
    print(f"Exact block reason: {blocked_decision.message}")
    print(f"Override actor: {args.actor}")
    print(f"Override reason: {args.reason}")
    print(f"Blocked decision_id: {blocked_decision.decision_id}")
    print(f"Override decision_id: {override_decision.decision_id}")
    print(f"Override ledger id: {override_event.get('override_id')}")
    print(f"JSON export: {json_path}")
    print(f"CSV export:  {csv_path}")
    print(f"Override chain verified: {chain.get('valid')} (checked={chain.get('checked')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
