import os
import re

from releasegate.utils.paths import safe_join_under

# Base directory for all audit artifacts
# Can be overridden by env var for CI/CD or docker mounts
AUDIT_ROOT = os.getenv("COMPLIANCEBOT_AUDIT_ROOT", "audit_bundles")


_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


def _clean_path_part(value: str) -> str:
    """
    Produce a filesystem-safe path component (no separators, no traversal).
    """
    text = str(value or "").strip()
    text = text.replace("/", "_").replace("\\", "_").replace("..", "_")
    text = _UNSAFE_CHARS.sub("_", text).strip("._-")
    return text or "unknown"


def get_audit_log_path(repo_name: str) -> str:
    """
    Returns text file path: audit_bundles/logs/<repo>/audit.ndjson
    """
    clean_repo = _clean_path_part(repo_name)
    return str(safe_join_under(AUDIT_ROOT, "logs", clean_repo, "audit.ndjson"))

def get_bundle_path(repo_name: str, pr_number: int, audit_id: str) -> str:
    """
    Returns folder path: audit_bundles/<repo>/pr_<num>/<audit_id>/
    """
    clean_repo = _clean_path_part(repo_name)
    clean_audit_id = _clean_path_part(audit_id)
    return str(safe_join_under(AUDIT_ROOT, clean_repo, f"pr_{int(pr_number)}", clean_audit_id))
