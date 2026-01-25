from typing import Dict, Any
from compliancebot.ingestion.labeling.base import BaseLabeler, LabelResult

class HotfixLabeler(BaseLabeler):
    """
    Labels a change as risky if it matches hotfix patterns (branch/title).
    """

    def label(self, entity: Dict[str, Any]) -> LabelResult:
        message = entity.get("message", "").lower()
        branches = entity.get("branches", [])

        # 1. Branch Check
        for b in branches:
            if "hotfix" in b.lower() or "patch" in b.lower():
                return LabelResult(
                    value=1,
                    source="hotfix",
                    confidence=0.85,
                    reason=f"Committed on hotfix branch: {b}"
                )

        # 2. Message Check
        if "hotfix" in message or "urgent" in message:
            return LabelResult(
                value=1,
                source="hotfix",
                confidence=0.75,
                reason="Commit message contains 'hotfix' or 'urgent'"
            )

        return LabelResult(value=None, source="hotfix", confidence=0.0)
