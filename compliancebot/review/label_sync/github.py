import requests
from typing import List

class GitHubLabelSync:
    """GitHub label sync implementation."""
    
    def __init__(self, repo: str, token: str):
        self.repo = repo
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        }
        self.base_url = f"https://api.github.com/repos/{repo}"
    
    def ensure_label_exists(self, name: str, color: str, description: str) -> None:
        """Create label if it doesn't exist."""
        url = f"{self.base_url}/labels"
        payload = {"name": name, "color": color, "description": description}
        
        try:
            resp = requests.post(url, json=payload, headers=self.headers)
            if resp.status_code == 201:
                print(f"Created label: {name}")
            elif resp.status_code == 422:
                # Label already exists
                pass
        except Exception as e:
            print(f"Warning: Could not create label {name}: {e}")
    
    def get_labels(self, pr_number: int) -> List[str]:
        """Get current labels on PR."""
        url = f"{self.base_url}/issues/{pr_number}/labels"
        
        try:
            resp = requests.get(url, headers=self.headers)
            if resp.status_code == 200:
                return [label["name"] for label in resp.json()]
        except Exception as e:
            print(f"Warning: Could not fetch labels: {e}")
        
        return []
    
    def add_labels(self, pr_number: int, labels: List[str]) -> None:
        """Add labels to PR."""
        url = f"{self.base_url}/issues/{pr_number}/labels"
        
        try:
            resp = requests.post(url, json={"labels": labels}, headers=self.headers)
            if resp.status_code in [200, 201]:
                print(f"Added labels: {', '.join(labels)}")
        except Exception as e:
            print(f"Warning: Could not add labels: {e}")
    
    def remove_labels(self, pr_number: int, labels: List[str]) -> None:
        """Remove labels from PR."""
        for label in labels:
            # URL-encode label name
            import urllib.parse
            encoded = urllib.parse.quote(label, safe='')
            url = f"{self.base_url}/issues/{pr_number}/labels/{encoded}"
            
            try:
                resp = requests.delete(url, headers=self.headers)
                if resp.status_code == 200:
                    print(f"Removed label: {label}")
            except Exception as e:
                print(f"Warning: Could not remove label {label}: {e}")
