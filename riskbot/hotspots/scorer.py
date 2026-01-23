from typing import List
from datetime import datetime
from riskbot.hotspots.types import FileRiskRecord

def score_files(file_data: dict, min_samples: int = 10) -> List[FileRiskRecord]:
    """
    Score and rank files by risk.
    
    Guardrail: files with < min_samples changes are flagged as low-confidence
    to avoid noisy rankings.
    
    Args:
        file_data: Dict from file_risk.aggregate_file_risks()
        min_samples: Minimum changes required for high confidence (default 10)
        
    Returns:
        List of FileRiskRecord, sorted by risk (descending)
    """
    records = []
    
    for file_path, data in file_data.items():
        # Filter junk/config files
        if file_path.endswith((".md", ".txt", ".lock")) or ".github/" in file_path:
            continue
            
        # Calculate risk score (deterministic formula)
        incident_rate = data.get("incident_rate", 0.0)
        churn_score = data.get("churn_score", 0.0)
        samples = data.get("changes", 0)
        
        # Weighted formula: 60% incident history, 40% churn pressure
        risk_score = 0.6 * incident_rate + 0.4 * churn_score
        
        # Sample-size guardrail: downweight low-sample files
        if samples < min_samples:
            risk_score *= 0.5  # Reduce confidence
        
        # Bucketing
        if risk_score >= 0.70:
            risk_bucket = "HIGH"
        elif risk_score >= 0.40:
            risk_bucket = "MEDIUM"
        else:
            risk_bucket = "LOW"
        
        # Parse last_touched
        last_touched_str = data.get("last_touched")
        try:
            last_touched = datetime.fromisoformat(last_touched_str) if last_touched_str else datetime.now()
        except:
            last_touched = datetime.now()
        
        # Create record
        record = FileRiskRecord(
            file_path=file_path,
            risk_score=risk_score,
            risk_bucket=risk_bucket,
            incident_rate=incident_rate,
            churn_score=churn_score,
            recent_churn=int(data.get("recent_churn", 0)),
            samples=data.get("changes", 0),
            incidents=data.get("incidents", 0),
            last_touched=last_touched,
            contributors=[],  # Will be populated by explainer
            explanation=[]  # Will be populated by explainer
        )
        
        records.append(record)
    
    # Sort deterministically
    records.sort(key=lambda r: (
        -r.risk_score,  # DESC
        -r.incident_rate,  # DESC
        -r.churn_score,  # DESC
        r.file_path  # ASC (tie-break)
    ))
    
    return records
