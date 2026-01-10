import argparse
import sys
import json
from riskbot.features.git_diff import get_diff_stats, get_changed_files, get_file_stats
from riskbot.features.churn import get_churn_stats
from riskbot.features.tests import has_test_changes
from riskbot.features.paths import get_critical_path_touches
from riskbot.scoring.rules_v1 import calculate_score
from riskbot.scoring.explain import generate_markdown_report
from riskbot.integrations.github import post_comment

def main():
    parser = argparse.ArgumentParser(description="Calculate PR risk score")
    parser.add_argument("--base", required=True, help="Base commit SHA or branch")
    parser.add_argument("--head", required=True, help="Head commit SHA or branch")
    parser.add_argument("--pr", type=int, help="PR number (for posting comments)")
    parser.add_argument("--repo", help="Repository name (e.g. owner/repo)")
    parser.add_argument("--post-comment", action="store_true", help="Post comment to GitHub")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of Markdown")
    
    args = parser.parse_args()
    
    # 1. Feature Extraction
    print(f"Analyzing diff between {args.base} and {args.head}...")
    
    try:
        files = get_changed_files(args.base, args.head)
        diff_stats = get_diff_stats(args.base, args.head)
        file_stats = get_file_stats(args.base, args.head)
        churn_stats = get_churn_stats(files)
        critical = get_critical_path_touches(files)
        tests_changed = has_test_changes(files)
    except Exception as e:
        print(f"Error extracting features: {e}")
        sys.exit(1)
        
    features = {
        "diff": diff_stats,
        "files": files,
        "file_types": file_stats,
        "churn": churn_stats,
        "paths": critical,
        "tests": tests_changed
    }
    
    # 2. Scoring
    score_data = calculate_score(features)
    
    # 3. Output
    if args.json:
        print(json.dumps(score_data, indent=2))
        return

    report = generate_markdown_report(score_data)
    print("\n--- REPORT ---\n")
    print(report)
    print("\n--------------\n")
    
    # 4. Integration
    if args.post_comment:
        if args.pr and args.repo:
            print(f"Posting comment to {args.repo} PR #{args.pr}...")
            post_comment(args.repo, args.pr, report)
        else:
            print("Error: --pr and --repo are required for --post-comment")
            sys.exit(1)

if __name__ == "__main__":
    main()
