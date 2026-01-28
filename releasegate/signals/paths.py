from typing import List
from compliancebot.config import CRITICAL_PATHS

def get_critical_path_touches(files: List[str]) -> List[str]:
    """Return which critical paths are touched."""
    touched = set()
    for f in files:
        for critical in CRITICAL_PATHS:
            if f.startswith(critical) or f"/{critical}" in f:
                touched.add(critical)
    return list(touched)

