import git
import pandas as pd
import os
import datetime
from typing import List, Dict, Any

class GitIngest:
    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path
        self.repo = git.Repo(repo_path)

    def get_commit_history(self, limit: int = 100) -> pd.DataFrame:
        """
        Extract commit history and features from the git log.
        """
        commits = []
        
        # Iterate over recent commits
        for commit in self.repo.iter_commits(max_count=limit):
            
            # Basic Metadata
            stats = commit.stats.total
            files_changed = commit.stats.files
            
            # File extensions & Critical Paths
            extensions = set()
            critical_touched = False
            critical_paths = ["auth/", "db/", "config/", "infra/", "api/"]
            
            file_list = list(files_changed.keys())
            
            for file_path in file_list:
                ext = os.path.splitext(file_path)[1]
                if ext:
                    extensions.add(ext)
                
                if any(cp in file_path for cp in critical_paths):
                    critical_touched = True

            # Structure the row
            row = {
                "hexsha": commit.hexsha,
                "author": commit.author.name,
                "email": commit.author.email,
                "date": datetime.datetime.fromtimestamp(commit.committed_date),
                "message": commit.message.strip(),
                "files_count": stats.get("files", 0),
                "lines_added": stats.get("insertions", 0),
                "lines_deleted": stats.get("deletions", 0),
                "files_json": file_list,
                "extensions": list(extensions),
                "is_critical": critical_touched
            }
            commits.append(row)
            
        return pd.DataFrame(commits)

    def analyze_hotspots(self, df: pd.DataFrame, top_n: int = 5):
        """
        Identify files with the most churn (changes).
        """
        all_files = []
        for file_list in df['files_json']:
            all_files.extend(file_list)
            
        return pd.Series(all_files).value_counts().head(top_n)

if __name__ == "__main__":
    # Example Usage
    ingest = GitIngest(".")
    df = ingest.get_commit_history(limit=50)
    print(f"Ingested {len(df)} commits.")
    print("\nTop 5 Hotspots:")
    print(ingest.analyze_hotspots(df))
    
    # Save for inspection
    df.to_json("data/git_history.json", orient="records", indent=2)
    print("\nSaved history to data/git_history.json")
