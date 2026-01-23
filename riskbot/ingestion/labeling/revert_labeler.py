from typing import Dict, Any
from riskbot.ingestion.labeling.base import BaseLabeler, LabelResult

class RevertLabeler(BaseLabeler):
    """
    Labels a change as risky if it was reverted by a later commit.
    """
    def label(self, entity: Dict[str, Any]) -> LabelResult:
        # In a real system, this requires looking AHEAD in history.
        # For this MVP, we assume ingestion passes in `reverted_by` metadata if known.
        # OR we rely on the commit message of 'entity' saying "revert <sha>" to label <sha>.
        # BUT `label()` runs on the row itself.
        
        # Strategy A: The entity IS the revert commit. We don't label IT risky (it fixes risk).
        # We label the ORIGINAL. But our ingestion pipeline iterates linearly.
        
        # Strategy B: We assume `ingest_repo.py` pre-calculates "is_reverted" flag map.
        # The entity dict passed here should have that context.
        
        reverted_by = entity.get("reverted_by_sha")
        
        if reverted_by:
            return LabelResult(
                value=1,
                source="revert_chain",
                confidence=0.95,
                reason=f"Reverted by commit {reverted_by[:7]}"
            )
            
        return LabelResult(value=None, source="revert_chain", confidence=0.0)
