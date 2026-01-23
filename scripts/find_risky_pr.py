import sys, json, os, urllib.request
from dotenv import load_dotenv

load_dotenv()

import argparse

load_dotenv()

parser = argparse.ArgumentParser()
parser.add_argument("--repo", default="prometheus/prometheus")
args = parser.parse_args()

repo = args.repo
token = os.environ.get("GITHUB_TOKEN")

if not token:
    print("Error: GITHUB_TOKEN not set")
    sys.exit(1)

def get_open_prs():
    url = f"https://api.github.com/repos/{repo}/pulls?state=open&per_page=30"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "riskbot-test"
    })
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())

def get_pr_details(n):
    url = f"https://api.github.com/repos/{repo}/pulls/{n}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "riskbot-test"
    })
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())

try:
    prs = get_open_prs()
except Exception as e:
    print(f"Error fetching PRs: {e}")
    sys.exit(1)

best = None

print(f"Scanning {len(prs)} PRs...", file=sys.stderr)

for p in prs:
    n = p.get("number")
    if not n: 
        continue
    try:
        full = get_pr_details(n)
        churn = full.get("additions", 0) + full.get("deletions", 0)
        if best is None or churn > best[0]:
            best = (churn, n)
            # print(f"New max: #{n} ({churn})", file=sys.stderr)
    except Exception as e:
        # print(f"Failed to fetch #{n}: {e}", file=sys.stderr)
        continue

if best:
    print(best[1])
else:
    print("")
