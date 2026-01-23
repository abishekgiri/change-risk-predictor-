import json
from datetime import datetime
from typing import Dict, Any, List
from riskbot.review.types import ReviewPriorityResult

def to_json(result: ReviewPriorityResult, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Render ReviewPriorityResult as JSON dict.
    
    Args:
        result: ReviewPriorityResult
        context: Optional context (repo, risk_score, etc.)
        
    Returns:
        JSON-serializable dict
    """
    context = context or {}
    
    output = {
        "pr": result.pr_id,
        "priority": result.priority,
        "label": result.label,
        "rationale": result.rationale,
        "recommendation": result.recommendation,
        "generated_at": datetime.now().isoformat(),
        # Enterprise fields
        "repo": getattr(result, "repo", context.get("repo")),
        "data_quality": getattr(result, "data_quality", "FULL"), 
        "risk_score": getattr(result, "risk_score", context.get("risk_score")),
        "decision": getattr(result, "decision", context.get("decision"))
    }
    
    # Add context if available
    if "repo" in context:
        output["repo"] = context["repo"]
    if "risk_score" in context:
        output["risk_score"] = context["risk_score"]
    if "risk_prob" in context:
        output["risk_prob"] = context["risk_prob"]
    if "decision" in context:
        output["decision"] = context["decision"]
    if "top_contributors" in context:
        output["top_contributors"] = context["top_contributors"]
    
    return output

def to_json_multi(results: List[Dict[str, Any]], repo: str) -> Dict[str, Any]:
    """
    Render multiple PR priorities as JSON.
    
    Args:
        results: List of dicts with pr, title, priority, etc.
        repo: Repository name
        
    Returns:
        JSON-serializable dict
    """
    return {
        "repo": repo,
        "generated_at": datetime.now().isoformat(),
        "prs": results
    }

def to_markdown(result: ReviewPriorityResult) -> str:
    """
    Render ReviewPriorityResult as markdown.
    
    Args:
        result: ReviewPriorityResult
        
    Returns:
        Markdown string
    """
    lines = []
    
    # Emoji based on priority
    emoji = "🔴" if result.priority == "P0" else "🟡" if result.priority == "P1" else "🟢"
    
    lines.append(f"{emoji} **Review Priority: {result.priority} — {result.label}**")
    lines.append("")
    lines.append("**Reason:**")
    for r in result.rationale:
        lines.append(f"• {r}")
    lines.append("")
    lines.append("**Recommendation:**")
    lines.append(result.recommendation)
    
    return "\n".join(lines)

def to_table(result: ReviewPriorityResult) -> str:
    """
    Render ReviewPriorityResult as table.
    
    Args:
        result: ReviewPriorityResult
        
    Returns:
        Table string
    """
    lines = []
    lines.append("=" * 60)
    lines.append(f"PR #{result.pr_id} — {result.priority} ({result.label})")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Reason:")
    for r in result.rationale:
        lines.append(f"  • {r}")
    lines.append("")
    lines.append(f"Recommendation: {result.recommendation}")
    lines.append("=" * 60)
    
    return "\n".join(lines)
