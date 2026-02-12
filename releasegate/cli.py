import argparse
import sys
import os
import json
import yaml
from datetime import datetime, timezone

from releasegate.storage.base import resolve_tenant_id

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
    eval_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    
    # Enforce Command (Retroactive)
    enforce_p = sub.add_parser("enforce", help="Enforce a previous decision")
    enforce_p.add_argument("--decision-id", required=True)
    enforce_p.add_argument("--dry-run", action="store_true", help="Plan actions but do not execute")
    enforce_p.add_argument("--tenant", required=True, help="Tenant/org identifier")

    # Audit Command
    audit_p = sub.add_parser("audit", help="Query audit logs.")
    audit_sub = audit_p.add_subparsers(dest="audit_cmd", required=True)
    
    # audit list
    audit_list = audit_sub.add_parser("list", help="List recent decisions")
    audit_list.add_argument("--repo", required=True)
    audit_list.add_argument("--limit", type=int, default=20)
    audit_list.add_argument("--status", choices=["ALLOWED", "BLOCKED", "CONDITIONAL", "SKIPPED", "ERROR"])
    audit_list.add_argument("--pr", type=int)
    audit_list.add_argument("--tenant", required=True, help="Tenant/org identifier")
    
    # audit show
    audit_show = audit_sub.add_parser("show", help="Show full decision details")
    audit_show.add_argument("--decision-id", required=True)
    audit_show.add_argument("--tenant", required=True, help="Tenant/org identifier")

    lint_p = sub.add_parser("lint-policies", help="Validate compiled policy schema and lint policy logic.")
    lint_p.add_argument("--policy-dir", default="releasegate/policy/compiled")
    lint_p.add_argument("--format", default="text", choices=["text", "json"])
    lint_p.add_argument(
        "--no-schema-strict",
        action="store_true",
        help="Allow invalid policy files to be skipped (lint still runs on valid files).",
    )

    jira_validate_p = sub.add_parser(
        "validate-jira-config",
        help="Validate Jira transition/role mapping config and optional Jira connectivity.",
    )
    jira_validate_p.add_argument(
        "--transition-map",
        default="releasegate/integrations/jira/jira_transition_map.yaml",
        help="Path to jira_transition_map.yaml",
    )
    jira_validate_p.add_argument(
        "--role-map",
        default="releasegate/integrations/jira/jira_role_map.yaml",
        help="Path to jira_role_map.yaml",
    )
    jira_validate_p.add_argument("--policy-dir", default="releasegate/policy/compiled")
    jira_validate_p.add_argument("--check-jira", action="store_true", help="Validate mappings against live Jira metadata")
    jira_validate_p.add_argument("--format", default="text", choices=["text", "json"])

    bundle_validate_p = sub.add_parser(
        "validate-policy-bundle",
        help="Deploy-time guard: validate compiled policy bundle load + lint.",
    )
    bundle_validate_p.add_argument("--policy-dir", default="releasegate/policy/compiled")
    bundle_validate_p.add_argument("--format", default="text", choices=["text", "json"])
    bundle_validate_p.add_argument(
        "--no-schema-strict",
        action="store_true",
        help="Allow invalid policy files to be skipped while validating policy bundle.",
    )

    checkpoint_p = sub.add_parser("checkpoint-override", help="Create signed override-ledger root checkpoint.")
    checkpoint_p.add_argument("--repo", required=True)
    checkpoint_p.add_argument("--cadence", default="daily", choices=["daily", "weekly"])
    checkpoint_p.add_argument("--pr", type=int)
    checkpoint_p.add_argument("--at", help="ISO timestamp for checkpoint cutoff (default: now)")
    checkpoint_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    checkpoint_p.add_argument("--format", default="text", choices=["text", "json"])

    simulate_p = sub.add_parser("simulate-policies", help="Run what-if simulation over recent decisions.")
    simulate_p.add_argument("--repo", required=True)
    simulate_p.add_argument("--limit", type=int, default=100)
    simulate_p.add_argument("--policy-dir", default="releasegate/policy/compiled")
    simulate_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    simulate_p.add_argument("--format", default="text", choices=["text", "json"])

    proof_p = sub.add_parser("proof-pack", help="Export audit evidence bundle for a decision.")
    proof_p.add_argument("--decision-id", required=True)
    proof_p.add_argument("--format", default="json", choices=["json", "zip"])
    proof_p.add_argument("--checkpoint-cadence", default="daily", choices=["daily", "weekly"])
    proof_p.add_argument("--tenant", required=True, help="Tenant/org identifier")
    proof_p.add_argument("--output", help="Output file path (required for zip)")

    verify_proof_pack_p = sub.add_parser(
        "verify-proof-pack",
        help="Verify proof-pack artifact integrity offline.",
    )
    verify_proof_pack_p.add_argument("file", help="Path to proof-pack JSON or ZIP file")
    verify_proof_pack_p.add_argument("--format", default="text", choices=["text", "json"])
    verify_proof_pack_p.add_argument("--signing-key", help="Checkpoint signing key for verification (HMAC)")
    verify_proof_pack_p.add_argument("--key-file", help="Path to trusted key file/key map for verification")

    sub.add_parser("db-migrate", help="Apply forward-only DB migrations.")
    sub.add_parser("db-migration-status", help="Show applied DB migrations.")
    sub.add_parser("version", help="Print version.")
    return p

def main() -> int:
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        sys.argv.append("--help")
        
    p = build_parser()
    args = p.parse_args()
    if hasattr(args, "tenant") and getattr(args, "tenant", None):
        os.environ["RELEASEGATE_TENANT_ID"] = args.tenant

    if args.cmd == "version":
        print("releasegate 0.1.0")
        return 0

    if args.cmd == "db-migrate":
        from releasegate.storage.migrate import migrate

        current = migrate()
        print(json.dumps({"status": "ok", "schema_version": current}, indent=2))
        return 0

    if args.cmd == "db-migration-status":
        from releasegate.storage.migrate import migration_status

        print(json.dumps(migration_status(), indent=2))
        return 0

    if args.cmd == "analyze-pr":
        # Set token if provided
        if args.token:
            os.environ["GITHUB_TOKEN"] = args.token

        # Load config (optional thresholds)
        config = {}
        if args.config and os.path.exists(args.config):
            try:
                with open(args.config, "r") as f:
                    config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Failed to load config {args.config}: {e}", file=sys.stderr)

        try:
            from releasegate.server import get_pr_details, get_pr_metrics, post_pr_comment, create_check_run
        except Exception as e:
            print(f"Error importing GitHub helpers: {e}", file=sys.stderr)
            return 1

        from releasegate.integrations.github_risk import (
            build_issue_risk_property,
            classify_pr_risk,
            extract_jira_issue_keys,
            score_for_risk_level,
        )

        pr_number = int(args.pr)
        pr_data = get_pr_details(args.repo, pr_number)
        metrics = get_pr_metrics(args.repo, pr_number)
        github_risk = config.get("github_risk", {}) if isinstance(config, dict) else {}
        risk_level = classify_pr_risk(
            metrics,
            high_changed_files=int(github_risk.get("high_changed_files", 20)),
            medium_additions=int(github_risk.get("medium_additions", 300)),
            high_total_churn=int(github_risk.get("high_total_churn", 800)),
        )
        risk_score = score_for_risk_level(risk_level)
        decision = "BLOCK" if risk_level == "HIGH" else "WARN" if risk_level == "MEDIUM" else "PASS"

        reasons = [f"Heuristic classification from GitHub metadata: {risk_level}"]

        issue_keys = sorted(extract_jira_issue_keys(pr_data.get("title"), pr_data.get("body")))
        attached_issue_keys = []
        if issue_keys:
            try:
                from releasegate.integrations.jira.client import JiraClient

                jc = JiraClient()
                payload = build_issue_risk_property(
                    repo=args.repo,
                    pr_number=pr_number,
                    risk_level=risk_level,
                    metrics=metrics,
                )
                for key in issue_keys:
                    if jc.set_issue_property(key, "releasegate_risk", payload):
                        attached_issue_keys.append(key)
            except Exception as e:
                print(f"Warning: Failed to attach Jira risk property: {e}", file=sys.stderr)

        output = {
            "control_result": decision,
            "severity": risk_score,
            "severity_level": risk_level,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "decision": decision,
            "reasons": reasons,
            "metrics": {
                "changed_files_count": metrics.changed_files,
                "additions": metrics.additions,
                "deletions": metrics.deletions,
                "total_churn": metrics.total_churn,
            },
            "attached_issue_keys": attached_issue_keys,
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
            print(f"Decision: {decision}")
            print(f"Risk: {risk_level} ({risk_score})")
            if reasons:
                print("Reasons:")
                for r in reasons:
                    print(f" - {r}")

        # Optional PR comment/check
        if args.post_comment and args.repo and pr_number:
            comment_body = (
                f"## {decision} Compliance Check\n\n"
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
        if mode == "block" and decision == "BLOCK":
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
            existing_data = AuditReader.get_decision_by_evaluation_key(
                new_decision.evaluation_key,
                tenant_id=resolve_tenant_id(args.tenant),
            )
            
            if existing_data:
                # Reuse the existing decision
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
            tenant_id = resolve_tenant_id(args.tenant)
            
            # 1. Fetch Decision
            data = AuditReader.get_decision(args.decision_id, tenant_id=tenant_id)
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
            tenant_id = resolve_tenant_id(args.tenant)
            rows = AuditReader.list_decisions(
                repo=args.repo,
                limit=args.limit,
                status=args.status,
                pr=args.pr,
                tenant_id=tenant_id,
            )
            print(json.dumps(rows, indent=2, default=str)) # Simple JSON output for list
            
        elif args.audit_cmd == "show":
            row = AuditReader.get_decision(args.decision_id, tenant_id=resolve_tenant_id(args.tenant))
            if row:
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

    if args.cmd == "lint-policies":
        from releasegate.policy.lint import lint_compiled_policies, format_lint_report

        report = lint_compiled_policies(
            policy_dir=args.policy_dir,
            strict_schema=not args.no_schema_strict,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_lint_report(report))
        return 0 if report.get("ok") else 1

    if args.cmd == "validate-policy-bundle":
        from releasegate.policy.lint import lint_compiled_policies, format_lint_report

        report = lint_compiled_policies(
            policy_dir=args.policy_dir,
            strict_schema=not args.no_schema_strict,
        )
        report = {
            **report,
            "validation_profile": "deploy_bundle_v1",
        }
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_lint_report(report))
        return 0 if report.get("ok") else 1

    if args.cmd == "validate-jira-config":
        from releasegate.integrations.jira.validate import (
            format_jira_validation_report,
            validate_jira_config_files,
        )

        report = validate_jira_config_files(
            transition_map_path=args.transition_map,
            role_map_path=args.role_map,
            policy_dir=args.policy_dir,
            check_jira=args.check_jira,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_jira_validation_report(report))
        return 0 if report.get("ok") else 1

    if args.cmd == "checkpoint-override":
        from releasegate.audit.checkpoints import create_override_checkpoint

        tenant_id = resolve_tenant_id(args.tenant)
        result = create_override_checkpoint(
            repo=args.repo,
            cadence=args.cadence,
            pr=args.pr,
            at=args.at,
            tenant_id=tenant_id,
        )
        if args.format == "json":
            print(json.dumps(result, indent=2, default=str))
        else:
            payload = result.get("payload", {})
            print(f"Checkpoint created: {result.get('path')}")
            print(f"Tenant: {payload.get('tenant_id')}")
            print(f"Repo: {payload.get('repo')}")
            print(f"Cadence: {payload.get('cadence')}")
            print(f"Period: {payload.get('period_id')}")
            print(f"Root Hash: {payload.get('root_hash')}")
            print(f"Events: {payload.get('event_count')}")
        return 0

    if args.cmd == "simulate-policies":
        from releasegate.policy.simulation import simulate_policy_impact

        tenant_id = resolve_tenant_id(args.tenant)
        report = simulate_policy_impact(
            repo=args.repo,
            limit=args.limit,
            policy_dir=args.policy_dir,
            tenant_id=tenant_id,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2, default=str))
        else:
            print(f"Tenant: {report.get('tenant_id')}")
            print(f"Repo: {report.get('repo')}")
            print(f"Policy Dir: {report.get('policy_dir')}")
            print(f"Policy Hash: {report.get('policy_hash')}")
            print(f"Total Decisions: {report.get('total_rows')}")
            print(f"Simulated: {report.get('simulated_rows')}  Unsimulated: {report.get('unsimulated_rows')}")
            print(f"Changed: {report.get('changed_count')}")
            print(f"Would Newly Block: {report.get('would_newly_block')}")
            print(f"Would Unblock: {report.get('would_unblock')}")
        return 0

    if args.cmd == "proof-pack":
        from releasegate.audit.checkpoints import (
            load_override_checkpoint,
            period_id_for_timestamp,
            verify_override_checkpoint,
        )
        from releasegate.audit.overrides import list_override_chain_segment, list_overrides, verify_override_chain
        from releasegate.audit.reader import AuditReader
        from releasegate.audit.proof_packs import record_proof_pack_generation
        from releasegate.decision.hashing import (
            compute_decision_hash,
            compute_input_hash,
            compute_policy_hash_from_bindings,
            compute_replay_hash,
        )
        from releasegate.utils.canonical import sha256_json

        tenant_id = resolve_tenant_id(args.tenant)

        row = AuditReader.get_decision(args.decision_id, tenant_id=tenant_id)
        if not row:
            print("Decision not found.", file=sys.stderr)
            return 1

        raw = row.get("full_decision_json")
        if not raw:
            print("Decision payload missing full_decision_json.", file=sys.stderr)
            return 1

        decision_snapshot = json.loads(raw) if isinstance(raw, str) else raw
        repo = row.get("repo")
        pr_number = row.get("pr_number")
        created_at = row.get("created_at")

        override_snapshot = None
        chain_proof = None
        checkpoint_proof = None
        checkpoint_snapshot = None
        ledger_segment = []
        period_id = ""
        if repo:
            overrides = list_overrides(repo=repo, limit=500, pr=pr_number, tenant_id=tenant_id)
            override_snapshot = next((o for o in overrides if o.get("decision_id") == args.decision_id), None)
            ledger_segment = list_override_chain_segment(
                repo=repo,
                pr=pr_number,
                tenant_id=tenant_id,
                limit=2000,
            )
            chain_proof = verify_override_chain(repo=repo, pr=pr_number, tenant_id=tenant_id)
            period_id = period_id_for_timestamp(created_at, cadence=args.checkpoint_cadence)
            checkpoint_snapshot = load_override_checkpoint(
                repo=repo,
                cadence=args.checkpoint_cadence,
                period_id=period_id,
                tenant_id=tenant_id,
            )
            checkpoint_proof = verify_override_checkpoint(
                repo=repo,
                cadence=args.checkpoint_cadence,
                period_id=period_id,
                pr=pr_number,
                tenant_id=tenant_id,
            )

        input_hash = decision_snapshot.get("input_hash") or compute_input_hash(decision_snapshot.get("input_snapshot", {}))
        policy_hash = decision_snapshot.get("policy_hash") or compute_policy_hash_from_bindings(
            decision_snapshot.get("policy_bindings") or decision_snapshot.get("policy_snapshot") or []
        )
        decision_hash = decision_snapshot.get("decision_hash") or compute_decision_hash(
            release_status=str(decision_snapshot.get("release_status") or "UNKNOWN"),
            reason_code=decision_snapshot.get("reason_code"),
            policy_bundle_hash=str(decision_snapshot.get("policy_bundle_hash") or ""),
            inputs_present=decision_snapshot.get("inputs_present") or {},
        )
        replay_hash = decision_snapshot.get("replay_hash") or compute_replay_hash(
            input_hash=input_hash,
            policy_hash=policy_hash,
            decision_hash=decision_hash,
        )
        checkpoint_signature = ""
        signing_key_id = ""
        checkpoint_id = ""
        if checkpoint_snapshot:
            checkpoint_signature = ((checkpoint_snapshot.get("signature") or {}).get("value") or "")
            signing_key_id = ((checkpoint_snapshot.get("signature") or {}).get("key_id") or "")
            checkpoint_id = ((checkpoint_snapshot.get("ids") or {}).get("checkpoint_id") or "")

        proof_pack_id = record_proof_pack_generation(
            decision_id=args.decision_id,
            output_format=args.format.lower(),
            bundle_version="audit_proof_v1",
            repo=repo,
            pr_number=pr_number,
            tenant_id=tenant_id,
        )

        bundle = {
            "schema_name": "proof_pack",
            "schema_version": "proof_pack_v1",
            "bundle_version": "audit_proof_v1",
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ids": {
                "decision_id": args.decision_id,
                "checkpoint_id": checkpoint_id,
                "proof_pack_id": proof_pack_id,
                "policy_bundle_hash": decision_snapshot.get("policy_bundle_hash") or "",
                "repo": repo or "",
                "pr_number": pr_number if pr_number is not None else "",
                "period_id": period_id,
                "checkpoint_cadence": args.checkpoint_cadence,
            },
            "integrity": {
                "canonicalization": "releasegate-canonical-json-v1",
                "hash_alg": "sha256",
                "input_hash": input_hash,
                "policy_hash": policy_hash,
                "decision_hash": decision_hash,
                "replay_hash": replay_hash,
                "ledger": {
                    "ledger_tip_hash": ledger_segment[-1].get("event_hash") if ledger_segment else "",
                    "ledger_record_id": ledger_segment[-1].get("override_id") if ledger_segment else "",
                },
                "signatures": {
                    "checkpoint_signature": checkpoint_signature,
                    "signing_key_id": signing_key_id,
                },
            },
            "decision_id": args.decision_id,
            "repo": repo,
            "pr_number": pr_number,
            "decision_snapshot": decision_snapshot,
            "policy_snapshot": decision_snapshot.get("policy_bindings", []),
            "input_snapshot": decision_snapshot.get("input_snapshot", {}),
            "override_snapshot": override_snapshot,
            "ledger_segment": ledger_segment,
            "checkpoint_snapshot": checkpoint_snapshot,
            "chain_proof": chain_proof,
            "checkpoint_proof": checkpoint_proof,
        }
        export_checksum = sha256_json(bundle)
        bundle["export_checksum"] = export_checksum
        bundle["proof_pack_id"] = proof_pack_id

        if args.format == "json":
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(bundle, f, indent=2, default=str)
            print(json.dumps(bundle, indent=2, default=str))
            return 0

        if not args.output:
            print("--output is required for zip format", file=sys.stderr)
            return 1

        import io
        import zipfile

        memory = io.BytesIO()
        with zipfile.ZipFile(memory, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bundle.json", json.dumps(bundle, indent=2, default=str))
            zf.writestr("integrity.json", json.dumps(bundle["integrity"], indent=2, default=str))
            zf.writestr("decision_snapshot.json", json.dumps(bundle["decision_snapshot"], indent=2, default=str))
            zf.writestr("policy_snapshot.json", json.dumps(bundle["policy_snapshot"], indent=2, default=str))
            zf.writestr("input_snapshot.json", json.dumps(bundle["input_snapshot"], indent=2, default=str))
            zf.writestr("override_snapshot.json", json.dumps(bundle["override_snapshot"], indent=2, default=str))
            zf.writestr("ledger_segment.json", json.dumps(bundle["ledger_segment"], indent=2, default=str))
            zf.writestr("chain_proof.json", json.dumps(bundle["chain_proof"], indent=2, default=str))
            zf.writestr("checkpoint_proof.json", json.dumps(bundle["checkpoint_proof"], indent=2, default=str))
            zf.writestr("checkpoint_snapshot.json", json.dumps(bundle["checkpoint_snapshot"], indent=2, default=str))
        memory.seek(0)
        with open(args.output, "wb") as f:
            f.write(memory.getvalue())
        print(f"Wrote proof pack: {args.output}")
        return 0

    if args.cmd == "verify-proof-pack":
        from releasegate.audit.proof_pack_verify import (
            ProofPackFileError,
            format_verification_summary,
            verify_proof_pack_file,
        )

        try:
            report = verify_proof_pack_file(
                args.file,
                signing_key=args.signing_key,
                key_file=args.key_file,
            )
        except ProofPackFileError as exc:
            payload = {
                "ok": False,
                "error_code": "PROOF_PACK_FILE_INVALID",
                "error_message": str(exc),
                "file": args.file,
            }
            if args.format == "json":
                print(json.dumps(payload, indent=2))
            else:
                print(f"verification: FAIL\nerror_code: {payload['error_code']}\nerror_message: {payload['error_message']}")
            return 3

        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_verification_summary(report))
        return 0 if report.get("ok") else 2

    return 2

if __name__ == "__main__":
    sys.exit(main())
