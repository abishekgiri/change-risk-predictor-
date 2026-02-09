import argparse
import sys
import os
import json
import yaml

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="releasegate")
    sub = p.add_subparsers(dest="cmd", required=True)

    analyze_p = sub.add_parser("analyze-pr", help="Analyze a PR and output decision.")
    analyze_p.add_argument("--repo", required=True, help="Repository name (owner/repo)")
    analyze_p.add_argument("--pr", required=True, help="PR number")
    analyze_p.add_argument("--token", help="GitHub token (optional, else uses GITHUB_TOKEN env)")
    analyze_p.add_argument("--config", default="compliancebot.yaml", help="Path to config yaml")
    analyze_p.add_argument("--output", help="Write JSON result to file")
    analyze_p.add_argument("--format", default="json", choices=["json", "text"])
    analyze_p.add_argument("--post-comment", action="store_true", help="Post PR comment")
    analyze_p.add_argument("--create-check", action="store_true", help="Create GitHub check run")
    analyze_p.add_argument("--no-bundle", action="store_true", help="(ignored) compatibility flag")

    eval_p = sub.add_parser("evaluate", help="Evaluate policies for a change (PR/release).")
    eval_p.add_argument("--repo", required=True)
    eval_p.add_argument("--pr", required=True)
    eval_p.add_argument("--format", default="text", choices=["text", "json"])
    eval_p.add_argument("--environment", choices=["PRODUCTION", "STAGING", "DEV", "UNKNOWN"], default="UNKNOWN")
    eval_p.add_argument("--include-context", action="store_true", help="Include full context in output")
    eval_p.add_argument("--enforce", action="store_true", help="Execute enforcement actions")
    eval_p.add_argument("--no-audit", action="store_true", help="Skip writing to audit log")
    
    # Enforce Command (Retroactive)
    enforce_p = sub.add_parser("enforce", help="Enforce a previous decision")
    enforce_p.add_argument("--decision-id", required=True)
    enforce_p.add_argument("--dry-run", action="store_true", help="Plan actions but do not execute")

    # Audit Command
    audit_p = sub.add_parser("audit", help="Query audit logs.")
    audit_sub = audit_p.add_subparsers(dest="audit_cmd", required=True)
    
    # audit list
    audit_list = audit_sub.add_parser("list", help="List recent decisions")
    audit_list.add_argument("--repo", required=True)
    audit_list.add_argument("--limit", type=int, default=20)
    audit_list.add_argument("--status", choices=["ALLOWED", "BLOCKED", "CONDITIONAL"])
    audit_list.add_argument("--pr", type=int)
    
    # audit show
    audit_show = audit_sub.add_parser("show", help="Show full decision details")
    audit_show.add_argument("--decision-id", required=True)

    sub.add_parser("version", help="Print version.")
    return p

def main() -> int:
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        sys.argv.append("--help")
        
    p = build_parser()
    args = p.parse_args()

    if args.cmd == "version":
        print("releasegate 0.1.0")
        return 0

    if args.cmd == "analyze-pr":
        # Set token if provided
        if args.token:
            os.environ["GITHUB_TOKEN"] = args.token

        # Load config (best-effort)
        config = {}
        if args.config and os.path.exists(args.config):
            try:
                with open(args.config, "r") as f:
                    config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Failed to load config {args.config}: {e}", file=sys.stderr)

        # Ensure repo is available to downstream config lookups
        config.setdefault("github", {})
        if isinstance(config.get("github"), dict):
            config["github"].setdefault("repo", args.repo)
        config.setdefault("repo_slug", args.repo)

        # Fetch PR metadata and files
        try:
            from releasegate.server import get_pr_details, get_pr_files, post_pr_comment, create_check_run
        except Exception as e:
            print(f"Error importing GitHub helpers: {e}", file=sys.stderr)
            return 1

        pr_number = int(args.pr)
        pr_data = get_pr_details(args.repo, pr_number)
        filenames, diff_stats, per_file_churn = get_pr_files(args.repo, pr_number)
        config["head_sha"] = pr_data.get("head", {}).get("sha", "")

        raw_signals = {
            "repo": args.repo,
            "pr_number": pr_number,
            "diff": {},  # Diff content not available via this path (MVP)
            "repo_slug": args.repo,
            "entity_type": "pr",
            "entity_id": str(pr_number),
            "timestamp": pr_data.get("created_at", "unknown"),
            "files_changed": filenames,
            "lines_added": diff_stats.get("loc_added", 0),
            "lines_deleted": diff_stats.get("loc_deleted", 0),
            "total_churn": diff_stats.get("total_churn", 0),
            "per_file_churn": per_file_churn,
            "touched_services": [],
            "linked_issue_ids": [],
            "author": pr_data.get("user", {}).get("login"),
            "branch": pr_data.get("head", {}).get("ref"),
        }

        # Evaluate policies
        from releasegate.engine import ComplianceEngine
        engine = ComplianceEngine(config)
        run_result = engine.evaluate(raw_signals)

        risk_score = run_result.metadata.get("core_risk_score", 0) or 0
        risk_level = run_result.metadata.get("core_risk_level", "UNKNOWN")

        reasons = []
        for p in run_result.results:
            if p.status in ["BLOCK", "WARN"]:
                for v in p.violations:
                    reasons.append(f"[{p.policy_id}] {v}")

        output = {
            "control_result": run_result.overall_status,
            "severity": risk_score,
            "severity_level": risk_level,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "decision": run_result.overall_status,
            "reasons": reasons,
            "evidence": run_result.metadata.get("phase3_findings", []),
            "model_version": run_result.metadata.get("raw_features", {}).get("feature_version"),
        }

        # Write JSON output if requested
        if args.output:
            try:
                with open(args.output, "w") as f:
                    json.dump(output, f, indent=2)
            except Exception as e:
                print(f"Error writing output {args.output}: {e}", file=sys.stderr)
                return 1

        if args.format == "json":
            print(json.dumps(output, indent=2))
        else:
            print(f"Decision: {run_result.overall_status}")
            print(f"Risk: {risk_level} ({risk_score})")
            if reasons:
                print("Reasons:")
                for r in reasons:
                    print(f" - {r}")

        # Optional PR comment/check
        if args.post_comment and args.repo and pr_number:
            comment_body = (
                f"## {run_result.overall_status} Compliance Check\n\n"
                f"**Severity**: {risk_level} ({risk_score})\n\n"
                + ("\n".join(f"- {r}" for r in reasons) if reasons else "_No policy violations found._")
            )
            try:
                post_pr_comment(args.repo, pr_number, comment_body)
            except Exception as e:
                print(f"Warning: Failed to post comment: {e}", file=sys.stderr)

        if args.create_check and args.repo and pr_number:
            try:
                create_check_run(
                    args.repo,
                    pr_data.get("head", {}).get("sha", ""),
                    risk_score,
                    risk_level,
                    reasons,
                    evidence=None
                )
            except Exception as e:
                print(f"Warning: Failed to create check run: {e}", file=sys.stderr)

        # Enforcement mode
        mode = os.getenv("COMPLIANCEBOT_ENFORCEMENT", "report_only")
        if mode == "block" and run_result.overall_status == "BLOCK":
            return 1
        return 0

    if args.cmd == "evaluate":
        try:
            from releasegate.context.builder import ContextBuilder
            from releasegate.context.types import EvaluationContext
            
            # TODO: Fetch real user/change details from GitHub API if --repo/--pr provided
            # For Phase 10 Step 2, we demo the Builder working with mock data (but structured correctly)
            
            # In real implementation:
            # pr_data = github_client.get_pr(args.repo, args.pr)
            
            ctx = (ContextBuilder()
                   # .with_pr_data(pr_data) # Future
                   .with_actor(user_id="mock-user", login="mock-user", role="Engineer", team="Product")
                   .with_change(
                       repo=args.repo, 
                       change_id=args.pr, 
                       files=["TODO: fetch files"], 
                       change_type="PR",
                       author_login="mock-user",
                       head_sha="a1b2c3d4e5f678901234567890abcdef12345678" # Mock SHA for demo
                    )
                   .with_environment(args.environment)
                   .check_change_window()
                   .build())

            # Load and Evaluate Policies
            from releasegate.policy.loader import PolicyLoader
            from releasegate.policy.evaluator import PolicyEvaluator
            
            loader = PolicyLoader()
            policies = loader.load_policies()
            if args.format != "json":
                print(f"Loaded policies: {len(policies)} from {loader.policy_dir}", file=sys.stderr)
            
            evaluator = PolicyEvaluator()
            result = evaluator.evaluate(ctx, policies)

            # Create Canonical Decision (in-memory candidate)
            from releasegate.decision.factory import DecisionFactory
            new_decision = DecisionFactory.create(ctx, result, policies)
            
            # 2. Check for Idempotency (Have we made this exact decision before?)
            from releasegate.audit.reader import AuditReader
            existing_data = AuditReader.get_decision_by_evaluation_key(new_decision.evaluation_key)
            
            if existing_data:
                # Reuse the existing decision
                import json
                from releasegate.decision.types import Decision
                
                decision_dict = json.loads(existing_data["full_decision_json"])
                decision = Decision(**decision_dict)
                is_new = False
            else:
                decision = new_decision
                is_new = True

            if args.format == "json":
                # Decision model has explicit schema, perfect for JSON
                print(decision.model_dump_json())
            else:
                print(f"Decision ID: {decision.decision_id}")
                if not is_new:
                     print(f"(Reused existing decision from {decision.timestamp})")
                     
                print(f"Context ID: {decision.context_id}")
                print(f"Status: {decision.release_status}")
                print(f"Message: {decision.message}")
                
                if decision.release_status == "BLOCKED":
                    print(f"Blocking Policies: {', '.join(decision.blocking_policies)}")
                    
                if decision.unlock_conditions:
                    print("Unlock Conditions:")
                    for cond in decision.unlock_conditions:
                        print(f"  - {cond}")
                
                if args.include_context:
                    print("\nFull Context:")
                    print(ctx.model_dump_json(indent=2))
            
            # Enforcement Execution
            if args.enforce:
                if args.format != "json":
                    print("\n[Enforcement] Planning actions...")
                
                from releasegate.enforcement.planner import EnforcementPlanner
                from releasegate.enforcement.runner import EnforcementRunner
                
                actions = EnforcementPlanner.plan(decision)
                runner = EnforcementRunner()
                results = runner.run(actions)
                
                if args.format != "json":
                     for res in results:
                         print(f"[{res.status}] {res.action.action_type} -> {res.detail}")

            # Audit Logging (Default: ON)
            # Only record if it's NEW and auditing is enabled
            if is_new and not args.no_audit:
                try:
                    from releasegate.audit.recorder import AuditRecorder
                    # Attempt to extract Repo/PR from context
                    repo = ctx.change.repository
                    # Try to parse PR number safely
                    try:
                        pr_number = int(ctx.change.change_id)
                    except:
                        pr_number = None
                        
                    AuditRecorder.record_with_context(decision, repo, pr_number)
                    if args.format != "json":
                        print(f"[Audit] Recorded decision {decision.decision_id}")
                except Exception as e:
                    print(f"[Audit] Failed to record: {e}", file=sys.stderr)
            elif not is_new and not args.no_audit and args.format != "json":
                # Only print this in text mode
                print(f"[Audit] Decision {decision.decision_id} already recorded.")

        except Exception as e:
            print(f"Error building context: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return 1
            
        return 0

    if args.cmd == "enforce":
        try:
            from releasegate.audit.reader import AuditReader
            from releasegate.enforcement.planner import EnforcementPlanner
            from releasegate.enforcement.runner import EnforcementRunner
            from releasegate.decision.types import Decision
            import json
            
            # 1. Fetch Decision
            data = AuditReader.get_decision(args.decision_id)
            if not data:
                print(f"Error: Decision {args.decision_id} not found.", file=sys.stderr)
                return 1
                
            # Parse canonical JSON back to Decision object
            # Note: We depend on pydantic to parse the JSON string stored in DB
            decision_dict = json.loads(data["full_decision_json"])
            decision = Decision(**decision_dict)
            
            # 2. Plan
            actions = EnforcementPlanner.plan(decision)
            
            if args.dry_run:
                print(f"Planned Actions for Decision {args.decision_id}:")
                print(json.dumps([a.model_dump(mode='json') for a in actions], indent=2))
                return 0
            
            # 3. Execute
            print(f"Executing enforcement for decision {args.decision_id}...")
            runner = EnforcementRunner()
            results = runner.run(actions)
            
            for res in results:
                print(f"[{res.status}] {res.action.action_type} -> {res.detail}")
                
        except Exception as e:
            print(f"Enforcement error: {e}", file=sys.stderr)
            return 1
        return 0

    if args.cmd == "audit":
        from releasegate.audit.reader import AuditReader
        
        if args.audit_cmd == "list":
            rows = AuditReader.list_decisions(
                repo=args.repo,
                limit=args.limit,
                status=args.status,
                pr=args.pr
            )
            import json
            print(json.dumps(rows, indent=2, default=str)) # Simple JSON output for list
            
        elif args.audit_cmd == "show":
            row = AuditReader.get_decision(args.decision_id)
            if row:
                import json
                # Try to parse the inner JSON for pretty printing
                try:
                    row["full_decision_json"] = json.loads(row["full_decision_json"])
                except:
                    pass
                print(json.dumps(row, indent=2, default=str))
            else:
                print("Decision not found.", file=sys.stderr)
                return 1
        return 0

    return 2

if __name__ == "__main__":
    sys.exit(main())
