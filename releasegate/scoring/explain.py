from typing import Dict, Any

def generate_markdown_report(score_data: Dict[str, Any]) -> str:
    """
    Generate a markdown report from the score data.
    """
    score = score_data["score"]
    level = score_data["risk_level"]
    reasons = score_data["reasons"]
    
    md = [
        f"## Change Risk Score: {score} ({level})",
        "",
        "**Top reasons:**"
    ]
    
    if not reasons:
        md.append("- No high-risk factors detected.")
    else:
        for r in reasons:
            md.append(f"- {r}")
    
    md.append("")
    md.append("**Suggested action:**" )
    
    if level == "HIGH":
        md.append("- Require 1 extra reviewer")
        md.append("- Run full integration test suite")
    elif level == "MEDIUM":
        md.append("- Careful review needed")
    else:
        md.append("- Standard review process")
    
    return "\n".join(md)
