from dotenv import load_dotenv
load_dotenv()

import argparse
import os
import json
import sys
import yaml
from typing import Dict, Any

from riskbot.features.feature_store import FeatureStore
from riskbot.scoring.risk_score import RiskScorer
from riskbot.config import RISK_DB_PATH

def load_config(config_path: str = "riskbot.yaml") -> Dict[str, Any]:
    if not os.path.exists(config_path):
        print(f"Config not found at {config_path}, using defaults.")
        return {}
    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}

def perform_analysis(repo_slug, pr_id, config, token=None):
    """
    Helper to run full analysis and return (result, explanation).
    """
    print(f"RiskBot Analysis starting for {repo_slug} PR #{pr_id}...")
    
    # 2. Construct Raw Signals 
    # For MVP CI, assuming we have GITHUB_TOKEN to fetch details via provider or raw API
    
    # Simple mode: Use GitHubProvider to fetch everything
    from riskbot.ingestion.providers.github_provider import GitHubProvider
    
    # Inject env vars or config
    provider_config = {"github": {"repo": repo_slug}}
    provider = GitHubProvider(provider_config)
    
    # Fetch Raw Data
    try:
        raw_signals = {
            "repo_slug": repo_slug,
            "entity_type": "pr",
            "entity_id": str(pr_id),
            "timestamp": "now", 
            "files_changed": [],
            "lines_added": 0,
            "lines_deleted": 0,
            "total_churn": 0,
            "per_file_churn": {},
            "touched_services": [],
            "linked_issue_ids": [],
            "author": "unknown",
            "branch": "unknown",
            "commit_count": 0,
            "file_history": {}
        }
        
        import requests
        import requests
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            print("Info: No GITHUB_TOKEN set. Attempting public access (rate limits apply).")
            
        # File Stats
        url_files = f"https://api.github.com/repos/{repo_slug}/pulls/{pr_id}/files"
        resp_files = requests.get(url_files, headers=headers)
        if resp_files.status_code == 200:
            files_data = resp_files.json()
            raw_signals["files_changed"] = [f['filename'] for f in files_data]
            raw_signals["lines_added"] = sum(f['additions'] for f in files_data)
            raw_signals["lines_deleted"] = sum(f['deletions'] for f in files_data)
            raw_signals["total_churn"] = raw_signals["lines_added"] + raw_signals["lines_deleted"]
            raw_signals["per_file_churn"] = {f['filename']: f['additions']+f['deletions'] for f in files_data}
        else:
            print(f"Warning: File fetch failed: {resp_files.status_code} {resp_files.text}")
        
        # PR Details
        url_pr = f"https://api.github.com/repos/{repo_slug}/pulls/{pr_id}"
        resp_pr = requests.get(url_pr, headers=headers)
        if resp_pr.status_code == 200:
            pr_data = resp_pr.json()
            raw_signals["author"] = pr_data.get("user", {}).get("login")
            raw_signals["branch"] = pr_data.get("head", {}).get("ref")
            body = pr_data.get("body") or ""
            import re
            raw_signals["linked_issue_ids"] = re.findall(r"#(\d+)", body)
            raw_signals["commit_count"] = pr_data.get("commits", 0)
            
        # Fetch File History
        raw_signals["file_history"] = {}
        top_files = raw_signals["files_changed"][:3]
        for f_path in top_files:
            try:
                url_hist = f"https://api.github.com/repos/{repo_slug}/commits?path={f_path}&per_page=30"
                resp_hist = requests.get(url_hist, headers=headers)
                if resp_hist.status_code == 200:
                    commits = resp_hist.json()
                    dates = [c["commit"]["author"]["date"] for c in commits]
                    raw_signals["file_history"][f_path] = dates
            except Exception as e:
                print(f"Warning: Failed to fetch history for {f_path}: {e}")

    except Exception as e:
        print(f"Error fetching PR data: {e}")
    
    # Build Features
    store = FeatureStore(config)
    features, explanations = store.build_features(raw_signals)
    
    # Score
    scorer = RiskScorer(config)
    result, explanation = scorer.calculate_score_with_explanation(features, raw_signals, explanations)
    
    return result, explanation


def analyze_pr(args):
    """
    Core Logic: Analyze a PR diff and output RiskResult.
    """
    # 1. Load Config
    config = load_config(args.config)
    token = args.token or os.getenv("GITHUB_TOKEN")
    
    result, explanation = perform_analysis(args.repo, args.pr, config, token)
    
    # 5. Output
    print(json.dumps(result, indent=2))
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
    
    # Output explanation separately
    safe_repo = args.repo.replace("/", "__")
    explanation_path = args.output.replace(".json", f"_explanation__{safe_repo}__pr_{args.pr}.json") if args.output else f"explanation__{safe_repo}__pr_{args.pr}.json"
    with open(explanation_path, "w") as f:
        json.dump(explanation, f, indent=2)
    
    # Render markdown
    from riskbot.explain import markdown as md
    explanation_md = md.render(explanation)
    md_path = args.output.replace(".json", f"_explanation__{safe_repo}__pr_{args.pr}.md") if args.output else f"explanation__{safe_repo}__pr_{args.pr}.md"
    with open(md_path, "w") as f:
        f.write(explanation_md)
    
    print(f"\nExplanation written to {explanation_path} and {md_path}")
            
    # 6. Enforcement
    enforce_mode = os.getenv("RISKBOT_ENFORCEMENT") or \
                   config.get("scoring", {}).get("enforcement", "report_only")
                   
    decision = result["decision"]
    
    if enforce_mode == "report_only":
        print(f"Report-Only Mode: Decision={decision} -> EXIT 0")
        sys.exit(0)
    
    if decision == "FAIL":
        print(f"Blocking: Decision=FAIL -> EXIT 1")
        sys.exit(1)
    elif decision == "WARN":
        print(f"Warning: Decision=WARN -> EXIT 2")
        sys.exit(2)
    else:
        print(f"Passing: Decision=PASS -> EXIT 0")
        sys.exit(0)

def pick_hard(args):
    """
    Demo mode: Runs analysis on known hard/interesting PRs.
    """
    # Known interesting PRs (Hardcoded Test Suite)
    test_suite = {
        "prometheus/prometheus": [
            {"pr": 17911, "mode": "tiny_critical", "desc": "Small change (6 LOC) to promql/ (Critical)"},
            {"pr": 17855, "mode": "huge_churn", "desc": "Extreme Churn (21k LOC)"},
            {"pr": 17907, "mode": "mixed", "desc": "Medium Churn + Critical (TSDB)"}
        ],
        "etcd-io/etcd": [
            {"pr": 17751, "mode": "hard_reject", "desc": "Critical Config Change"}
        ],
        "hashicorp/terraform": [
            {"pr": 37934, "mode": "hard_reject", "desc": "Critical API Change + High Churn"}
        ]
    }
    
    repo = args.repo
    mode = args.mode
    
    target_prs = []
    
    # Select PRs
    for r, prs in test_suite.items():
        if repo and r != repo:
            continue
        for entry in prs:
            if mode and entry["mode"] != mode:
                continue
            target_prs.append((r, entry))
            
    if not target_prs:
        print(f"No matching PRs found for repo={repo}, mode={mode}")
        return
        
    print(f"🔬 Running Hard Test Suite ({len(target_prs)} PRs)...\n")
    
    for r, entry in target_prs:
        print(f"=== Case: {entry['desc']} ({r} #{entry['pr']}) ===")
        
        class MockArgs:
            repo = r
            pr = str(entry['pr'])
            verbose = False
            token = args.token 
            dry_run = True 
            config = args.config
            output = None 
            
        try:
            analyze_pr(MockArgs())
        except Exception as e:
            print(f"❌ Failed: {e}")
        print("\n" + "-"*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="RiskBot CI CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    # analyze-pr
    p_analyze = subparsers.add_parser("analyze-pr", help="Analyze a PR")
    p_analyze.add_argument("--repo", required=True, help="owner/repo")
    p_analyze.add_argument("--pr", type=int, required=True, help="PR ID")
    p_analyze.add_argument("--token", help="GitHub Personal Access Token")
    p_analyze.add_argument("--config", default="riskbot.yaml", help="Path to config")
    p_analyze.add_argument("--output", default="risk_result.json", help="Output JSON path")
    
    # hotspots
    p_hotspots = subparsers.add_parser("hotspots", help="Identify predictive bug hotspots")
    p_hotspots.add_argument("--repo", required=True, help="owner/repo")
    p_hotspots.add_argument("--top", type=int, default=20, help="Number of top files to show")
    p_hotspots.add_argument("--since", default="30d", help="Time window: 30d, 90d, or all (default: 30d)")
    p_hotspots.add_argument("--format", choices=["table", "json", "markdown"], default="markdown", help="Output format")
    p_hotspots.add_argument("--output", help="Output file path (optional)")
    p_hotspots.add_argument("--min-samples", type=int, default=10, help="Minimum changes for high confidence (default: 10)")
    p_hotspots.add_argument("--config", default="riskbot.yaml", help="Path to config")

    # review-priority
    p_review = subparsers.add_parser("review-priority", help="Compute review priority for PR(s)")
    p_review.add_argument("--repo", required=True, help="owner/repo")
    p_review.add_argument("--pr", type=int, help="PR ID (single PR mode)")
    p_review.add_argument("--token", help="GitHub Personal Access Token")
    p_review.add_argument("--open", action="store_true", help="Analyze all open PRs (repo-wide mode)")
    p_review.add_argument("--config", default="riskbot.yaml", help="Path to config")
    p_review.add_argument("--format", choices=["table", "json", "markdown"], default="table", help="Output format")
    p_review.add_argument("--out", help="Output file path (optional)")
    p_review.add_argument("--sync-labels", action="store_true", help="Auto-apply PR labels (requires permissions)")
    p_review.add_argument("--dry-run", action="store_true", help="Test label sync without modifying PRs")

    # pick-hard (Test Suite)
    hard_parser = subparsers.add_parser("pick-hard", help="Run analysis on known hard/interesting PRs")
    hard_parser.add_argument("--repo", help="Filter by repository")
    hard_parser.add_argument("--mode", choices=["tiny_critical", "huge_churn", "hard_reject", "mixed"], help="Filter by test scenario")
    hard_parser.add_argument("--token", help="GitHub Personal Access Token")
    hard_parser.add_argument("--config", default="riskbot.yaml", help="Path to config")
    
    args = parser.parse_args()
    
    if args.command == "analyze-pr":
        analyze_pr(args)
    elif args.command == "hotspots":
        analyze_hotspots(args)
    elif args.command == "review-priority":
        review_priority(args)
    elif args.command == "pick-hard":
        pick_hard(args)
    else:
        parser.print_help()

def review_priority(args):
    """
    Compute review priority for PR(s).
    """
    from riskbot.review import engine, render
    from riskbot.review.label_sync import GitHubLabelSync, sync_labels
    from riskbot.scoring.risk_score import RiskScorer
    from riskbot.features.feature_store import FeatureStore
    import os
    
    config = load_config(args.config)
    token = args.token or os.getenv("GITHUB_TOKEN")
    
    if args.pr:
        # Single PR mode
        print(f"Computing review priority for {args.repo} PR #{args.pr}...")
        
        # 1. Run real analysis
        risk_result, explanation_report = perform_analysis(args.repo, args.pr, config, token)
        
        # 2. Compute Priority from REAL result
        result = engine.compute_review_priority(
            pr_id=str(args.pr),
            risk_result=risk_result,
            explanation_report=explanation_report,
            config=config.get("review_priority", {})
        )
        
        # Safety Guard: If data is partial, prevent P0 escalation unless critical path is proven
        if risk_result.get("data_quality") != "FULL" and result.priority == "P0":
            # Downgrade to P1 for safety
            result.priority = "P1"
            result.label = "High (Partial Data)"
            result.rationale.insert(0, "⚠ Partial data fetch; downgraded from P0 (Immediate) for safety.")
            result.recommendation = "Check PR manually. RiskBot could not fully analyze."
        
        # Render output
        if args.format == "json":
            context = {"repo": args.repo, "risk_score": risk_result["risk_score"], "decision": risk_result["decision"]}
            output = json.dumps(render.to_json(result, context), indent=2)
        elif args.format == "markdown":
            output = render.to_markdown(result)
        else:  # table
            output = render.to_table(result)
        
        print(output)
        
        if args.out:
            with open(args.out, "w") as f:
                f.write(output)
            print(f"\nOutput written to {args.out}")
        
        # Label sync (if enabled)
        if args.sync_labels:
            if token:
                try:
                    provider = GitHubLabelSync(args.repo, token)
                    label_config = config.get("review_priority", {}).get("label_sync", {})
                    
                    # Override dry_run from CLI
                    if args.dry_run:
                        label_config["dry_run"] = True
                    
                    if label_config.get("enabled", True):
                        sync_result = sync_labels(provider, args.pr, result.priority, label_config)
                        
                        if sync_result.get("dry_run"):
                            if sync_result.get("no_changes"):
                                print(f"\n✓ Labels already correct: {sync_result.get('would_add', [''])[0] if not sync_result.get('would_add') else result.priority} (no changes needed)")
                            else:
                                print("\n🔍 DRY RUN - No changes made:")
                                if sync_result.get("would_add"):
                                    print(f"  Would add: {', '.join(sync_result['would_add'])}")
                                if sync_result.get("would_remove"):
                                    print(f"  Would remove: {', '.join(sync_result['would_remove'])}")
                        else:
                            if sync_result.get("no_changes"):
                                print(f"\n✓ Labels already correct: {sync_result.get('current_label')} (no changes)")
                            else:
                                if sync_result.get("added"):
                                    print(f"\n✓ Applied labels: {', '.join(sync_result['added'])}")
                                if sync_result.get("removed"):
                                    print(f"✓ Removed labels: {', '.join(sync_result['removed'])}")
                        
                        if sync_result.get("errors"):
                            print(f"⚠ Warnings: {'; '.join(sync_result['errors'])}")
                except Exception as e:
                    print(f"\n⚠ Label sync failed: {e}")
            else:
                print("\n⚠ GITHUB_TOKEN not set, skipping label sync")
        
    elif args.open:
        # Repo-wide mode
        print(f"Analyzing open PRs for {args.repo}...")
        
        # Mock data (in production, fetch from GitHub API)
        # Fetch from GitHub if token available
        prs_to_analyze = []
        
        if token:
            try:
                import requests
                headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
                url = f"https://api.github.com/repos/{args.repo}/pulls?state=open&per_page=30"
                resp = requests.get(url, headers=headers)
                
                if resp.status_code == 200:
                    raw_prs = resp.json()
                    print(f"Found {len(raw_prs)} open PRs.")
                    
                    for p in raw_prs:
                        pr_num = p["number"]
                        # Analyze each PR
                        risk_result, _ = perform_analysis(args.repo, pr_num, config, token)
                        
                        # Compute Priority
                        priority_result = engine.compute_review_priority(
                            str(pr_num), risk_result, {}, config.get("review_priority", {})
                        )
                        
                        prs_to_analyze.append({
                            "pr": pr_num,
                            "title": p["title"][:40],
                            "priority": priority_result.priority,
                            "risk_score": risk_result["risk_score"],
                            "decision": risk_result["decision"]
                        })
                else:
                    print(f"Warning: Failed to fetch open PRs ({resp.status_code}). Using mock data.")
            except Exception as e:
                print(f"Warning: Error fetching open PRs: {e}. Using mock data.")
        
        if not prs_to_analyze:
            print("⚠ Using MOCK data (set GITHUB_TOKEN to see real PRs)")
            prs_to_analyze = [
                {"pr": 42, "title": "Refactor auth flow", "priority": "P0", "risk_score": 81, "decision": "FAIL"},
                {"pr": 38, "title": "Update docs", "priority": "P2", "risk_score": 15, "decision": "PASS"},
                {"pr": 35, "title": "Payment retry logic", "priority": "P1", "risk_score": 55, "decision": "WARN"}
            ]
            
        mock_prs = prs_to_analyze
        
        if args.format == "json":
            output = json.dumps(render.to_json_multi(mock_prs, args.repo), indent=2)
            print(output)
        else:
            # Table format
            print("\n" + "="*60)
            print(f"{'PR':<8} {'Title':<30} {'Priority':<10}")
            print("="*60)
            
            for pr in mock_prs:
                print(f"#{pr['pr']:<7} {pr['title']:<30} {pr['priority']:<10}")
            
            print("="*60)
        
        if args.out:
            with open(args.out, "w") as f:
                if args.format == "json":
                    f.write(output)
                else:
                    f.write("Table output not saved to file")
            print(f"\nOutput written to {args.out}")
    else:
        print("Error: Must specify either --pr or --open")



def analyze_hotspots(args):
    """
    Generate predictive bug hotspot report.
    """
    from riskbot.hotspots import file_risk, scorer, explain, report
    
    print(f"Analyzing hotspots for {args.repo}...")
    
    # Parse time window
    since_str = args.since.lower()
    if since_str == "all":
        window_days = 365 * 10  # 10 years (effectively all)
    elif since_str.endswith("d"):
        window_days = int(since_str[:-1])
    else:
        window_days = 30  # Default
    
    # 1. Aggregate file-level data
    file_data = file_risk.aggregate_file_risks(args.repo, window_days=window_days)
    
    if not file_data:
        print("No file data found.")
        return
    
    # 2. Score and rank
    records = scorer.score_files(file_data, min_samples=args.min_samples)

    
    # 3. Add explanations
    for record in records:
        explain.explain_file_risk(record)
    
    # 4. Render output
    if args.format == "markdown":
        output = report.render_markdown(records, args.top)
    elif args.format == "json":
        output = report.render_json(records, args.top)
    else:  # table
        output = report.render_table(records, args.top)
    
    # 5. Output
    print(output)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"\nReport written to {args.output}")


if __name__ == "__main__":
    main()
