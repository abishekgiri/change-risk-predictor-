from typing import Dict, Any, List, Optional
from compliancebot.ux.types import ExplanationFactor, DecisionExplanation
from compliancebot.ux.remediation import get_remediation

class ExplanationEngine:
    """
    Deterministic rule engine for converting features -> human explanations.
    """
    
    def generate(self, features: Dict[str, Any], decision: str, risk_score: int) -> DecisionExplanation:
        factors = []
        
        # 1. Evaluate Deterministic Rules
        # Rule: High Churn
        churn = features.get("total_churn", 0)
        if churn > 500:
            factors.append(ExplanationFactor(
                label="Extremely High Code Churn",
                evidence=f"Change touches {churn} lines (Threshold: 500)",
                severity=0.9,
                remediation=get_remediation("high_churn")
            ))
        elif churn > 200:
            factors.append(ExplanationFactor(
                label="High Code Churn",
                evidence=f"Change touches {churn} lines",
                severity=0.6,
                remediation=get_remediation("medium_churn")
            ))
        
        # Rule: Hotspots
        # Assuming features["hotspots"] is a list of risky files
        hotspots = features.get("risky_files", []) or features.get("hotspots", [])
        if hotspots:
            top_hotspot = hotspots[0]
            factors.append(ExplanationFactor(
                label="Critical Hotspot Modified",
                evidence=f"Modifies historical hotspot: {top_hotspot}",
                severity=0.8,
                remediation=get_remediation("hotspot_file")
            ))
        
        # Rule: Dependency Changes
        if features.get("dependency_change"):
            factors.append(ExplanationFactor(
                label="Dependency Manifest Modified",
                evidence="Changes detected in package.json/requirements.txt",
                severity=0.7,
                remediation=get_remediation("new_dependency")
            ))
        
        # Rule: Sensitive Files (Secrets/Auth)
        if features.get("sensitive_files_touched"):
            factors.append(ExplanationFactor(
                label="Sensitive Logic Modified",
                evidence="Touches auth/security paths",
                severity=0.85,
                remediation=get_remediation("sensitive_file")
            ))

        # 2. Sort by Severity
        factors.sort(key=lambda x: x.severity, reverse=True)
        
        # 3. Generate Summary & Narrative
        if decision == "BLOCK":
            summary = "Deployment BLOCKED due to high risk factors."
        elif decision == "WARN":
            summary = "Deployment allowed with WARNINGS."
        else:
            summary = "Deployment APPROVED (Standard Risk)."
        
        narrative = self._build_narrative(summary, factors, risk_score)
        
        return DecisionExplanation(
            summary=summary,
            factors=factors,
            narrative=narrative
        )

    def _build_narrative(self, summary: str, factors: List[ExplanationFactor], score: int) -> str:
        """
        Constructs a readable paragraph.
        """
        text = [f"{summary} (Risk Score: {score}/100)"]
        
        if not factors:
            text.append("No specific high-risk factors detected.")
            return "\n\n".join(text)
        
        text.append("Primary Drivers:")
        for f in factors[:3]: # Top 3
            text.append(f"- **{f.label}**: {f.evidence}")
        
        text.append("\nRecommended Actions:")
        top_factor = factors[0]
        for action in top_factor.remediation[:2]:
            text.append(f"- {action}")
        
        return "\n".join(text)

