def severity_from_impact(impact: float) -> str:
    """
    Deterministic mapping from impact score to severity label.
    
    Args:
        impact: 0-1 normalized contribution score
        
    Returns:
        "LOW" | "MEDIUM" | "HIGH"
    """
    # Round to avoid floating point ambiguity
    impact = round(impact, 4)
    
    if impact >= 0.30:
        return "HIGH"
    elif impact >= 0.15:
        return "MEDIUM"
    else:
        return "LOW"

def severity_from_feature(feature_name: str, feature_value: float, config: dict = None) -> str:
    """
    Optional: Map feature value to severity using config thresholds.
    Future enhancement for threshold-based severity.
    
    Args:
        feature_name: e.g., "churn_score"
        feature_value: 0-1 normalized value
        config: Optional config with custom thresholds
        
    Returns:
        "LOW" | "MEDIUM" | "HIGH"
    """
    # Default thresholds (can be overridden by config)
    thresholds = {
        "high": 0.7,
        "medium": 0.4
    }
    
    if config and "severity_thresholds" in config:
        thresholds.update(config["severity_thresholds"])
    
    if feature_value >= thresholds["high"]:
        return "HIGH"
    elif feature_value >= thresholds["medium"]:
        return "MEDIUM"
    else:
        return "LOW"
