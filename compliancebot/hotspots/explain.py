from typing import List
from compliancebot.hotspots.types import FileRiskRecord

def explain_file_risk(record: FileRiskRecord) -> FileRiskRecord:
    """
    Generate deterministic explanation for a file's risk.
    Modifies record in-place.
    
    Args:
        record: FileRiskRecord
    
    Returns:
        Updated FileRiskRecord with explanation and contributors
    """
    explanation = []
    contributors = []
    
    # 1. Incident rate explanation
    # Use raw incidents for display, but smoothed rate for threshold logic
    if record.incident_rate >= 0.25:
        # Calculate raw percentage for display to match incident count
        raw_rate = record.incidents / max(record.samples, 1)
        pct = int(raw_rate * 100)
        explanation.append(f"High historical incident rate: {pct}% ({record.incidents} incidents / {record.samples} changes)")
        contributors.append("high_incident_rate")
    elif record.incident_rate >= 0.10:
        raw_rate = record.incidents / max(record.samples, 1)
        pct = int(raw_rate * 100)
        explanation.append(f"Moderate incident rate: {pct}%")
        contributors.append("moderate_incident_rate")
    
    # 2. Churn explanation
    if record.churn_score >= 0.60:
        explanation.append(f"High recent churn ({record.recent_churn} LOC in last 30 days)")
        contributors.append("high_churn")
    elif record.churn_score >= 0.30:
        explanation.append(f"Moderate churn activity ({record.recent_churn} LOC)")
        contributors.append("moderate_churn")
    
    # 3. Multiple incidents
    if record.incidents >= 3:
        explanation.append(f"Involved in multiple incidents ({record.incidents} total)")
        contributors.append("multiple_incidents")
    
    # 4. Low sample warning
    if record.samples < 10:
        explanation.append(f"Limited history (only {record.samples} changes)")
        contributors.append("low_samples")
    
    # 5. Safe file (if no strong signals)
    if not explanation:
        explanation.append("Low risk: stable with minimal incident history")
        contributors.append("stable")
    
    # Update record
    record.explanation = explanation
    record.contributors = contributors
    
    return record
