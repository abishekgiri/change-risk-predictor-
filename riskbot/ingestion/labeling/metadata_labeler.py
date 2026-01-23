from typing import Dict, Any, List
from riskbot.ingestion.labeling.base import BaseLabeler, LabelResult
from riskbot.ingestion.providers.base import GitProvider

class MetadataLabeler(BaseLabeler):
    """
    Generic labeler that uses a GitProvider to fetch metadata (labels) 
    from linked issues/PRs. Decoupled from specific API logic.
    """
    def __init__(self, config: Dict[str, Any], provider: GitProvider):
        super().__init__(config)
        self.provider = provider
        self.risky_labels = set(self.config.get("labels", {}).get("risky_any_of", []))
        self.safe_labels = set(self.config.get("labels", {}).get("safe_any_of", []))

    def label(self, entity: Dict[str, Any]) -> LabelResult:
        linked_issues = entity.get("linked_issues", [])
        if not linked_issues:
            return LabelResult(value=None, source="metadata_label", confidence=0.0, reason="No linked issues")

        found_risky = []
        found_safe = []
        
        for ref in linked_issues:
            # Handle Dictionary format (Phase 5)
            if isinstance(ref, dict):
                ref_type = ref.get("type", "issue")
                ref_id = ref.get("id")
            else:
                # Backward compatibility for Phase 3/4 (simple strings)
                ref_type = "issue"
                ref_id = ref

            # Delegate fetching to provider
            if ref_type == "mr":
                # For MRs, use fetch_pr_details to get labels
                details = self.provider.fetch_pr_details(ref_id)
                labels = details.get("labels", [])
            else:
                labels = self.provider.fetch_issue_labels(ref_id)
            
            # Check matches
            current_labels = set(labels)
            risky_matches = current_labels.intersection(self.risky_labels)
            safe_matches = current_labels.intersection(self.safe_labels)
            
            if risky_matches:
                found_risky.extend(list(risky_matches))
            if safe_matches:
                found_safe.extend(list(safe_matches))

        if found_risky:
            return LabelResult(
                value=1, 
                source="metadata_label",
                confidence=0.95, 
                tags=found_risky,
                reason=f"Linked issue has risky labels: {found_risky}"
            )
        
        if found_safe:
             return LabelResult(
                value=0, 
                source="metadata_label",
                confidence=0.90, 
                tags=found_safe,
                reason=f"Linked issue has safe labels: {found_safe}"
            )

        return LabelResult(value=None, source="metadata_label", confidence=0.0, reason="No relevant labels found")
