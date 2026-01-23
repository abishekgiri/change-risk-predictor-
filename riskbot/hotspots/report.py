import json
from typing import List
from riskbot.hotspots.types import FileRiskRecord

def render_markdown(records: List[FileRiskRecord], top_n: int = 20) -> str:
    """
    Render hotspot report as markdown.
    
    Args:
        records: List of FileRiskRecord (sorted)
        top_n: Number of top files to include
        
    Returns:
        Markdown string
    """
    lines = []
    
    # Header
    lines.append(f"### 🔥 Predictive Bug Hotspots (Top {min(top_n, len(records))})")
    lines.append("")
    
    # Top files
    for i, record in enumerate(records[:top_n], 1):
        # Emoji based on bucket
        emoji = "🔴" if record.risk_bucket == "HIGH" else "🟡" if record.risk_bucket == "MEDIUM" else "🟢"
        
        # Title line
        lines.append(f"{i}. **{record.file_path}** — {emoji} {record.risk_bucket} ({record.risk_score:.2f})")
        
        # Explanation bullets
        for exp in record.explanation[:3]:  # Top 3 reasons
            lines.append(f"   - {exp}")
        
        lines.append("")  # Spacing
    
    return "\n".join(lines)

def render_json(records: List[FileRiskRecord], top_n: int = 20) -> str:
    """
    Render hotspot report as JSON.
    
    Args:
        records: List of FileRiskRecord (sorted)
        top_n: Number of top files to include
        
    Returns:
        JSON string
    """
    from datetime import datetime
    
    output = {
        "generated_at": datetime.now().isoformat(),
        "total_files": len(records),
        "top_files": []
    }
    
    for record in records[:top_n]:
        output["top_files"].append({
            "file_path": record.file_path,
            "risk_score": round(record.risk_score, 3),
            "risk_bucket": record.risk_bucket,
            "incident_rate": round(record.incident_rate, 3),
            "churn_score": round(record.churn_score, 3),
            "recent_churn": record.recent_churn,
            "samples": record.samples,
            "explanation": record.explanation,
            "contributors": record.contributors
        })
    
    return json.dumps(output, indent=2)

def render_table(records: List[FileRiskRecord], top_n: int = 20) -> str:
    """
    Render hotspot report as ASCII table.
    
    Args:
        records: List of FileRiskRecord (sorted)
        top_n: Number of top files to include
        
    Returns:
        Table string
    """
    lines = []
    
    # Header
    lines.append("=" * 80)
    lines.append(f"{'Rank':<6} {'File':<40} {'Risk':<8} {'Bucket':<8} {'Incidents':<12}")
    lines.append("=" * 80)
    
    # Rows
    for i, record in enumerate(records[:top_n], 1):
        file_display = record.file_path[:37] + "..." if len(record.file_path) > 40 else record.file_path
        incidents = f"{int(record.incident_rate * 100)}%"
        
        lines.append(f"{i:<6} {file_display:<40} {record.risk_score:.2f}   {record.risk_bucket:<8} {incidents:<12}")
    
    lines.append("=" * 80)
    
    return "\n".join(lines)
