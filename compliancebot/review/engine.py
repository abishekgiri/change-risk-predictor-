from typing import Dict, Any, List
from compliancebot.scoring.types import RiskResult
from compliancebot.explain.types import ExplanationReport
from compliancebot.review.types import ReviewPriorityResult
from compliancebot.review import priority

def compute_review_priority(
    pr_id: str,
    risk_result: RiskResult,
    explanation_report: ExplanationReport,
    hotspot_files: List[str] = None,
    config: Dict[str, Any] = None
) -> ReviewPriorityResult:
    """
    Compute deterministic review priority for a PR.
    
    Args:
        pr_id: PR identifier
        risk_result: RiskResult from scoring
        explanation_report: ExplanationReport from explainer
        hotspot_files: List of known high-risk files
        config: Optional config
    
    Returns:
        ReviewPriorityResult
    """
    config = config or {}
    hotspot_files = hotspot_files or []
    
    # Extract signals
    risk_score = risk_result["risk_score"]
    risk_level = risk_result["risk_level"]
    
    # Check for critical path
    contributors = [c["id"] for c in explanation_report.get("top_contributors", [])]
    critical_path_touched = "critical_path" in contributors
    
    # Check for hotspot files (would need file list from PR context)
    # For now, use dependency as proxy
    touches_hotspot = "file_history" in contributors or "dependency" in contributors
    
    # Blast radius
    components = risk_result.get("components", {})
    blast_radius = components.get("dependency", 0.0)
    
    # Determine priority
    pri = priority.determine_priority(
        risk_score=risk_score,
        risk_level=risk_level,
        contributors=contributors,
        critical_path_touched=critical_path_touched,
        touches_hotspot=touches_hotspot,
        blast_radius=blast_radius,
        config=config
    )
    
    # Generate rationale (Validated Reasons from scoring)
    # Use explanation summaries for cleaner, specific audit trail (Fix: Choice 2)
    rationale = []
    
    # Take top 3 contributors from explanation report
    for contrib in explanation_report.get("top_contributors", [])[:3]:
        rationale.append(contrib["summary"])
    
    # Fallback to risk_result['reasons'] only if explanation is empty (e.g. legacy/mock)
    if not rationale:
        rationale = risk_result.get("reasons", [])[:3]
    
    # Build result
    result = ReviewPriorityResult(
        pr_id=pr_id,
        priority=pri,
        label=priority.get_label(pri),
        rationale=rationale,
        recommendation=priority.get_recommendation(pri),
        repo=risk_result.get("repo_slug", ""), # Might not be in risk_result, check caller
        risk_score=risk_score,
        decision=risk_result.get("decision", ""),
        data_quality=risk_result.get("data_quality", "FULL")
    )
    
    return result
