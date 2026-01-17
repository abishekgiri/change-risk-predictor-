import argparse
import sys
from riskbot.storage.sqlite import add_label

def main():
    parser = argparse.ArgumentParser(description="Label a PR with an outcome")
    parser.add_argument("--repo", required=True, help="Repository name (owner/repo)")
    parser.add_argument("--pr", type=int, required=True, help="PR number")
    parser.add_argument("--label", required=True, choices=["incident", "rollback", "hotfix", "safe"], help="Outcome label")
    parser.add_argument("--severity", type=int, choices=[1, 2, 3, 4, 5], help="Severity (1-5), optional")
    
    args = parser.parse_args()
    
    try:
        add_label(args.repo, args.pr, args.label, args.severity)
        print(f"✅ Labeled {args.repo}#{args.pr} as '{args.label}'")
    except Exception as e:
        print(f"Error labeling PR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
