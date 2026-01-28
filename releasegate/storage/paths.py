import os

# Base directory for all audit artifacts
# Can be overridden by env var for CI/CD or docker mounts
AUDIT_ROOT = os.getenv("COMPLIANCEBOT_AUDIT_ROOT", "audit_bundles")

def get_audit_log_path(repo_name: str) -> str:
    """
    Returns text file path: audit_bundles/logs/<repo>/audit.ndjson
    """
    clean_repo = repo_name.replace("/", "_")
    return os.path.join(AUDIT_ROOT, "logs", clean_repo, "audit.ndjson")

def get_bundle_path(repo_name: str, pr_number: int, audit_id: str) -> str:
    """
    Returns folder path: audit_bundles/<repo>/pr_<num>/<audit_id>/
    """
    clean_repo = repo_name.replace("/", "_")
    return os.path.join(AUDIT_ROOT, clean_repo, f"pr_{pr_number}", audit_id)

