from typing import List, Dict, Set
from compliancebot.utils.shell import run_command

def get_changed_files(base: str, head: str) -> List[str]:
    """Return a list of changed file paths between base and head."""
    output = run_command(f"git diff --name-only {base}..{head}")
    if not output:
        return []
    return [line.strip() for line in output.split("\n") if line.strip()]

def get_diff_stats(base: str, head: str) -> Dict[str, int]:
    """Return loc_added, loc_deleted, and files_changed."""
    output = run_command(f"git diff --shortstat {base}..{head}")
    stat = {"files_changed": 0, "loc_added": 0, "loc_deleted": 0}
    if not output:
        return stat
    
    # Example output: " 3 files changed, 10 insertions(+), 5 deletions(-)"
    parts = output.split(",")
    for part in parts:
        part = part.strip()
        if "changed" in part:
            stat["files_changed"] = int(part.split()[0])
        elif "insertion" in part:
            stat["loc_added"] = int(part.split()[0])
        elif "deletion" in part:
            stat["loc_deleted"] = int(part.split()[0])
    
    return stat

def get_file_stats(base: str, head: str) -> Dict[str, int]:
    """Return count of file extensions changed."""
    files = get_changed_files(base, head)
    extensions = {}
    for f in files:
        ext = "." + f.split(".")[-1] if "." in f else "no_ext"
        extensions[ext] = extensions.get(ext, 0) + 1
    return extensions

