from compliancebot.explain.types import ExplanationReport, Contributor

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
    
    # 1. Header - Handle both Phase 1 (risk_score) and Phase 2 (control_result) formats
    if "risk_score" in report:
        # Phase 1 format
        score = report["risk_score"]
        prob = int(report.get("risk_prob", 0) * 100)
        level = report["risk_level"]
        decision = report["decision"]
        header = f"**ComplianceBot: {level}** — {score}/100 ({prob}%) — **{decision}**"
    else:
        # Phase 2 format
        control_result = report.get("control_result", "UNKNOWN")
        severity = report.get("severity", "UNKNOWN")
        header = f"**ComplianceBot: {severity}** — **{control_result}**"
    
    lines.append(header)
    lines.append("")
    
    # 2. Top Contributors (Phase 1 only)
    top = report.get("top_contributors", [])
    
    if not top:
        # Phase 2: Show violations instead
        violations = report.get("violations", [])
        if violations:
            lines.append("### Policy Violations")
            lines.append("")
            for v in violations:
                lines.append(f"- {v}")
            lines.append("")
        else:
            lines.append("*No policy violations detected.*")
            lines.append("")
    else:
        lines.append("### Top Risk Contributors")
        lines.append("")
        
        for i, contrib in enumerate(top[:3], 1): # Top 3
            # Bullet: Title (Severity) — Summary
            severity_emoji = _severity_emoji(contrib["severity"])
            bullet = f"{i}. **{contrib['title']}** ({severity_emoji} {contrib['severity']}) — {contrib['summary']}"
            lines.append(bullet)
            
            # Details (indented)
            for detail in contrib["details"][:3]: # Max 3 details
                lines.append(f" - {detail}")
            
            lines.append("") # Spacing
    
    # 3. Evidence
    all_evidence = []
    for contrib in top:
        all_evidence.extend(contrib.get("evidence", []))
    
    # Also check for direct evidence field (Phase 2)
    if "evidence" in report and isinstance(report["evidence"], dict):
        for k, v in report["evidence"].items():
            all_evidence.append(f"{k}: {v}")
    
    if all_evidence:
        lines.append("### Evidence")
        lines.append("")
        # Deduplicate and sort for determinism
        unique_evidence = sorted(set(all_evidence))
        for ev in unique_evidence[:5]: # Max 5 evidence items
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
        return ""
    elif severity == "MEDIUM":
        return "🟡"
    else:
        return "🟢"

