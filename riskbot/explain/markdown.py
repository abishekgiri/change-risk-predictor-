from riskbot.explain.types import ExplanationReport, Contributor

def render(report: ExplanationReport) -> str:
    """
    Render ExplanationReport to markdown for CI output.
    Deterministic: same report → same markdown string.
    
    Args:
        report: ExplanationReport
        
    Returns:
        Markdown string
    """
    lines = []
    
    # 1. Header
    score = report["risk_score"]
    prob = int(report["risk_prob"] * 100)
    level = report["risk_level"]
    decision = report["decision"]
    
    header = f"**RiskBot: {level}** — {score}/100 ({prob}%) — **{decision}**"
    lines.append(header)
    lines.append("")
    
    # 2. Top Contributors
    top = report["top_contributors"]
    
    if not top:
        lines.append("*No significant risk contributors detected.*")
    else:
        lines.append("### Top Risk Contributors")
        lines.append("")
        
        for i, contrib in enumerate(top[:3], 1):  # Top 3
            # Bullet: Title (Severity) — Summary
            severity_emoji = _severity_emoji(contrib["severity"])
            bullet = f"{i}. **{contrib['title']}** ({severity_emoji} {contrib['severity']}) — {contrib['summary']}"
            lines.append(bullet)
            
            # Details (indented)
            for detail in contrib["details"][:3]:  # Max 3 details
                lines.append(f"   - {detail}")
            
            lines.append("")  # Spacing
    
    # 3. Evidence (if any)
    all_evidence = []
    for contrib in top:
        all_evidence.extend(contrib.get("evidence", []))
    
    if all_evidence:
        lines.append("### Evidence")
        lines.append("")
        # Deduplicate and sort for determinism
        unique_evidence = sorted(set(all_evidence))
        for ev in unique_evidence[:5]:  # Max 5 evidence items
            lines.append(f"- {ev}")
        lines.append("")
    
    # 4. Metadata (collapsed)
    lines.append("<details>")
    lines.append("<summary>Metadata</summary>")
    lines.append("")
    lines.append(f"- **Feature Version**: {report.get('feature_version', 'unknown')}")
    lines.append(f"- **Model Version**: {report.get('model_version', 'baseline-v1')}")
    lines.append(f"- **Explain Version**: {report.get('explain_version', 'v1')}")
    lines.append("</details>")
    
    return "\n".join(lines)

def _severity_emoji(severity: str) -> str:
    """Map severity to emoji for visual clarity."""
    if severity == "HIGH":
        return "🔴"
    elif severity == "MEDIUM":
        return "🟡"
    else:
        return "🟢"
