import pandas as pd
from typing import Dict, List, Optional

class IncidentLabeler:
    """
    Auto-labels commits/PRs based on heuristic keywords and historical patterns.
    """
    def __init__(self):
        # Keywords suggesting a change caused a problem or is fixing one
        self.incident_keywords = [
            "incident", "sev1", "sev2", "outage", "downtime", 
            "rollback", "revert", "hotfix", "紧急", "bug", "critical", "fix:"
        ]
        # Keywords suggesting a change was safe/routine
        self.safe_keywords = [
            "docs", "chore", "style", "refactor", "test", 
            "bump version", "readme"
        ]

    def label_row(self, message: str, files: List[str]) -> int:
        """
        Returns label: 
        1 = Risky/Incident (this commit fixes a problem, implying the previous one was bad, 
        OR this commit IS a hotfix).
        0 = Safe
        -1 = Unknown
        """
        msg_lower = message.lower()
        
        # 1. Check for bad keywords
        if any(kw in msg_lower for kw in self.incident_keywords):
            return 1
        
        # 2. Check for safe keywords
        if any(kw in msg_lower for kw in self.safe_keywords):
            return 0
        
        return -1

    def apply_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply labeling logic to a dataframe of commits.
        """
        if 'message' not in df.columns:
            return df
        
        df['label'] = df.apply(
            lambda x: self.label_row(x['message'], x.get('files_json', [])), 
            axis=1
        )
        return df

if __name__ == "__main__":
    # Test with dummy data
    data = [
        {"message": "fix: critical bug in payments", "files_json": ["a.py"]},
        {"message": "docs: update readme", "files_json": ["README.md"]},
        {"message": "feat: add new user endpoint", "files_json": ["b.py"]},
        {"message": "revert: bad commit 123456", "files_json": ["c.py"]}
    ]
    df = pd.DataFrame(data)
    labeler = IncidentLabeler()
    labeled_df = labeler.apply_labels(df)
    print("Labeled Data:")
    print(labeled_df)
