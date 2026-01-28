import git
import pandas as pd
import os
from typing import Dict, Any, List

class PRParser:
    """
    Standardizer for PR Features.
    Ensures that Live PRs produce the exact same feature vector as historical commits.
    """
    def __init__(self, repo_path: str = "."):
        self.repo = git.Repo(repo_path)
        self.critical_paths = ["auth/", "db/", "config/", "infra/", "api/"]

    def extract_features(self, base_sha: str, head_sha: str) -> Dict[str, Any]:
        """
        Compare two commits (base vs head) and extract risk features.
        """
        try:
            # Get diff
            diffs = self.repo.commit(base_sha).diff(self.repo.commit(head_sha))
        except Exception as e:
            print(f"Error diffing {base_sha}..{head_sha}: {e}")
            return {}

        files_changed = []
        loc_added = 0
        loc_deleted = 0
        extensions = set()
        critical_touched = False
        
        for d in diffs:
            # File path
            path = d.b_path if d.b_path else d.a_path
            if not path:
                continue
            
            files_changed.append(path)
            
            # Extension
            ext = os.path.splitext(path)[1]
            if ext:
                extensions.add(ext)
            
            # Critical Path Check
            if any(cp in path for cp in self.critical_paths):
                critical_touched = True
            
            # Naive LOC stats (GitPython diff stats are expensive, so we approximate or fetch if needed)
            # For accurate stats, we'd need to read the blobs. 
            # For MVP, we count changed files as proxy for complexity if blobs are heavy.
            # But let's try to get stats if possible. d.diff is bytes.
            
            # For now, let's just count files and assume 0 loc if we can't easily parse without overhead
            # Improve this later with specific blob parsing if needed.
            
        return {
            "files_count": len(files_changed),
            "files_list": files_changed,
            "extensions": list(extensions),
            "is_critical": critical_touched,
            # LOC is harder with pure GitPython diff objects without reading blobs
            # We will leave simple counts for V1
            "loc_estimate": len(files_changed) * 10 
        }

if __name__ == "__main__":
    parser = PRParser()
    # Diff HEAD~1 vs HEAD (last commit)
    feat = parser.extract_features("HEAD~1", "HEAD")
    print("Parsed Feature Vector:")
    print(feat)
