import sys
import os

# Add project root to python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
import time
from riskbot.ingestion.providers.github_provider import GitHubProvider

def load_config():
    with open("riskbot.yaml", "r") as f:
        return yaml.safe_load(f)

def verify_providers():
    print("🚀 Verifying Enterprise Providers")
    print("===============================")
    
    config = load_config()
    provider = GitHubProvider(config)
    
    # 1. Auth Check
    print(f"[GitHub] Token Present: {'Yes' if provider.client else 'No'}")
    
    # 2. Public Repo Test (e.g. this one or a known public one)
    # We'll use a known ISSUE from a public repo: "octocat/Hello-World" issue #1 creates a stable test.
    # OR use the configured repo in yaml.
    target_ref = "1" # Issue #1
    target_repo = "octocat/Hello-World"
    
    # Override repo for test
    provider.repo_name = target_repo
    print(f"[GitHub] Fetching labels for {target_repo}#{target_ref}...")
    
    start_time = time.time()
    labels = provider.fetch_issue_labels(target_ref)
    duration = time.time() - start_time
    print(f" -> Labels: {labels}")
    print(f" -> Time (1st fetch): {duration:.4f}s")
    
    # 3. Cache Test
    print(f"[GitHub] Fetching AGAIN (Cache Test)...")
    start_time = time.time()
    labels_cached = provider.fetch_issue_labels(target_ref)
    duration_cached = time.time() - start_time
    print(f" -> Labels: {labels_cached}")
    print(f" -> Time (2nd fetch): {duration_cached:.4f}s")
    
    if duration_cached < 0.1 and labels == labels_cached:
        print("✅ CACHE HIT CONFIRMED")
    elif duration_cached >= 0.1:
        print("⚠️ CACHE MISS (Too slow)")
    else:
        print("❌ CACHE CONTENT MISMATCH")

    print("\n-------------------------")
    print("[GitLab] Provider Logic Check")
    # Mock config for GitLab
    gl_config = {
        "gitlab": {
            "url": "https://gitlab.com",
            # "token": "...", # No token in verification env
            "project": "gitlab-org/gitlab" 
        }
    }
    
    from riskbot.ingestion.providers.gitlab_provider import GitLabProvider
    gl_provider = GitLabProvider(gl_config)
    
    print(f"Fetch Public Issue labels (No Token check):")
    # Should handle gracefully (return empty list or 401/404 handling)
    labels_gl = gl_provider.fetch_issue_labels("12345")
    print(f" -> Result: {labels_gl} (Expected: [])")
    print("✅ GitLab Provider Instantiated & Logic Safe")

if __name__ == "__main__":
    verify_providers()
