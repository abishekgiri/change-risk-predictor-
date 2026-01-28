from typing import List
from compliancebot.config import TEST_PATHS

def has_test_changes(files: List[str]) -> bool:
    """Check if any of the changed files are test files."""
    for f in files:
        # Check against configured test paths
        for path in TEST_PATHS:
            if path in f:
                return True
        # Check for common test file naming conventions
        if "test_" in f or "_test.py" in f or ".spec." in f:
            return True
    
    return False
