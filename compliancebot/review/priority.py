from typing import Dict, Any, List

# Fixed recommendation text (enterprise trust)
RECOMMENDATIONS = {
    "P0": "Assign a senior reviewer. Avoid fast-merge.",
    "P1": "Standard review required.",
    "P2": "Safe to skim. Full deep review not required."
}

LABELS = {
    "P0": "Immediate",
    "P1": "Normal",
    "P2": "Low"
}

def determine_priority(
    risk_score: int,
    risk_level: str,
    contributors: List[str],
    critical_path_touched: bool,
    touches_hotspot: bool,
    blast_radius: float = 0.0,
    config: Dict[str, Any] = None
) -> str:
    """
    Deterministic priority assignment.
    
    Rules:
    - P0: risk_score >= 75 OR critical_path OR touches high-risk file
    - P1: risk_score >= 40
    - P2: risk_score < 40
    
    Optional boosters upgrade by ONE level:
    - High blast radius
    - Touches multiple hotspots
    
    Args:
        risk_score: 0-100
        risk_level: LOW/MEDIUM/HIGH
        contributors: List of contributor IDs
        critical_path_touched: Boolean
        touches_hotspot: Boolean
        blast_radius: 0-1
        config: Optional config
    
    Returns:
        Priority string: P0 | P1 | P2
    """
    config = config or {}
    
    # Base priority
    if risk_score >= 75 or critical_path_touched or touches_hotspot:
        priority = "P0"
    elif risk_score >= 40:
        priority = "P1"
    else:
        priority = "P2"
    
    # Optional boosters (upgrade by one level, never downgrade)
    blast_threshold = config.get("blast_radius_threshold", 0.6)
    
    if priority == "P2" and blast_radius >= blast_threshold:
        priority = "P1"
    elif priority == "P1" and blast_radius >= blast_threshold:
        priority = "P0"
    
    return priority

def get_recommendation(priority: str) -> str:
    """Get fixed recommendation text for priority."""
    return RECOMMENDATIONS.get(priority, RECOMMENDATIONS["P1"])

def get_label(priority: str) -> str:
    """Get label for priority."""
    return LABELS.get(priority, LABELS["P1"])
