from typing import Dict, Tuple, Any

class Thresholds:
 PASS = "PASS"
 WARN = "WARN"
 FAIL = "FAIL"
 
 LOW = "LOW"
 MEDIUM = "MEDIUM"
 HIGH = "HIGH"

def evaluate_decision(score: int, 
    prob: float, 
    config: Dict[str, Any],
    features: Dict[str, float] = None) -> Tuple[str, str]:
    """
    Determine CI Gate Decision (PASS/WARN/FAIL) and Risk Level.
    Returns: (decision, risk_level)
    """
    t_config = config.get("thresholds", {})
    
    # Defaults
    # Defaults (Strict Enterprise Mode)
    fail_score = t_config.get("fail_score", 20)
    warn_score = t_config.get("warn_score", 10)
    
    fail_prob = t_config.get("fail_prob", 0.25)
    warn_prob = t_config.get("warn_prob", 0.10)
    
    mode = t_config.get("mode", "score") # "score", "prob", "both"
    
    decision = Thresholds.PASS
    level = Thresholds.LOW
    
    # 1. Determine Level/Decision based on primary metric
    is_fail = False
    is_warn = False
    
    if mode == "prob" or mode == "both":
        if prob >= fail_prob: is_fail = True
        elif prob >= warn_prob: is_warn = True
    
    if mode == "score" or mode == "both":
        # OR logic if both
        if score >= fail_score: is_fail = True
        elif score >= warn_score: 
            if not is_fail: is_warn = True # maintain fail if already fail
    
    # 2. Safety Overrides (Hard Rules)
    # If explicitly requested via features arg
    if features:
        # Critical path safety net: Alway WARN if critical > 0.8
        if features.get("critical_path_score", 0) > 0.8:
            is_warn = True
        
        # Blast radius safety net
        if features.get("dependency_risk_score", 0) > 0.7:
            is_warn = True
    
    # 3. Finalize
    if is_fail:
        decision = Thresholds.FAIL
        level = Thresholds.HIGH
    elif is_warn:
        decision = Thresholds.WARN
        level = Thresholds.MEDIUM
    else:
        decision = Thresholds.PASS
        level = Thresholds.LOW
    
    return decision, level

