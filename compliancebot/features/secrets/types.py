"""
Secret finding types.
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class SecretFinding:
    """A detected secret in the code."""
    rule_id: str
    rule_name: str
    file_path: str
    line_number: Optional[int]
    line_content: str
    matched_value: str # The actual secret (will be masked)
    severity: str
    
    # Diff-specific fields
    diff_hunk: Optional[str] = None
    diff_line_index: Optional[int] = None
    
    def mask_value(self) -> str:
        """
        Mask the secret value for safe display.
        
        Shows first 4 and last 4 chars, masks the middle.
        """
        if len(self.matched_value) <= 8:
            return "****"
        
        return f"{self.matched_value[:4]}****{self.matched_value[-4:]}"

