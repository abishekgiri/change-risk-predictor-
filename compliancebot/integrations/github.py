import os
try:
    from github import Github, Auth
except ImportError:
    Github = None

def post_comment(repo_name: str, pr_number: int, body: str):
    """
    Post a comment to a GitHub PR.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Warning: GITHUB_TOKEN not set, skipping comment.")
        return
    
    if not Github:
        print("Warning: PyGithub not installed, skipping comment.")
        return

    auth = Auth.Token(token)
    g = Github(auth=auth)
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    pr.create_issue_comment(body)
    print(f"Posted comment to PR #{pr_number}")
