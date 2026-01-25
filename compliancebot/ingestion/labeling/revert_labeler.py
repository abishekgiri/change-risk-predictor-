from typing import Dict, Any
from compliancebot.ingestion.labeling.base import BaseLabeler, LabelResult

class RevertLabeler(BaseLabeler):
    """
    Labels a change as risky if it was reverted by a later commit.
    """
    def label(self, entity: Dict[str, Any]) -> LabelResult:
        # In a real system, this requires looking AHEAD in history.
        # For this MVP, we assume ingestion passes in `reverted_by` metadata if known.
        
        reverted_by = entity.get("reverted_by_sha")
        
        if reverted_by:
            return LabelResult(
                value=1,
                source="revert_chain",
                confidence=0.95,
                reason=f"Reverted by commit {reverted_by[:7]}"
            )
        
        return LabelResult(value=None, source="revert_chain", confidence=0.0)
