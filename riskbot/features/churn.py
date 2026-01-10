from typing import List, Dict
from riskbot.utils.shell import run_command

def get_file_churn(filepath: str, days: int = 30) -> int:
    """Return number of commits touching this file in the last N days."""
    cmd = f'git log --since="{days} days ago" --oneline -- "{filepath}"'
    output = run_command(cmd)
    if not output:
        return 0
    return len(output.split("\n"))

def get_churn_stats(files: List[str]) -> Dict[str, any]:
    """Calculate max, avg churn and identify hotspots."""
    if not files:
        return {"max_churn": 0, "avg_churn": 0, "hotspots": []}
        
    churns = {}
    for f in files:
        churns[f] = get_file_churn(f)
        
    max_churn = max(churns.values()) if churns else 0
    avg_churn = sum(churns.values()) / len(churns) if churns else 0
    
    # 5 is a placeholder threshold, maybe move to config
    hotspots = [f for f, count in churns.items() if count > 5]
    
    return {
        "max_churn": max_churn,
        "avg_churn": avg_churn,
        "hotspots": hotspots,
        "churn_map": churns
    }
