from typing import Dict, Any, List
from riskbot.features.types import RawSignals, FeatureVector
from riskbot.scoring.types import RiskResult
from riskbot.explain.types import Contributor, ExplanationReport
from riskbot.explain import templates, severity

# Deterministic tie-breaking priority
CONTRIBUTOR_PRIORITY = [
    "critical_path",
    "file_history",
    "dependency",
    "churn",
    "history_bucket",
    "routine_change"
]

def explain(raw: RawSignals, 
            features: FeatureVector, 
            risk: RiskResult, 
            config: Dict[str, Any] = None) -> ExplanationReport:
    """
    Generate deterministic explanation report from features and risk assessment.
    
    Args:
        raw: Raw signals (for evidence extraction)
        features: Normalized feature vector
        risk: Risk assessment result
        config: Configuration (weights, thresholds)
        
    Returns:
        ExplanationReport with ranked contributors
    """
    config = config or {}
    
    # 1. Compute impacts from baseline weights
    weights = config.get("weights", {
        "churn": 0.25,
        "criticality": 0.25,
        "file_history": 0.20,
        "dependency": 0.20,
        "history": 0.10
    })
    
    # Map weights to feature scores
    raw_impacts = {
        "churn": weights.get("churn", 0.25) * features.get("churn_score", 0.0),
        "critical_path": weights.get("criticality", 0.25) * features.get("critical_path_score", 0.0),
        "file_history": weights.get("file_history", 0.20) * features.get("file_historical_risk_score", 0.0),
        "dependency": weights.get("dependency", 0.20) * features.get("dependency_risk_score", 0.0),
        "history_bucket": weights.get("history", 0.10) * features.get("historical_risk_score", 0.0)
    }
    
    # 2. Normalize impacts (sum to 1)
    total_impact = sum(raw_impacts.values())
    
    if total_impact == 0:
        # Ultra-safe PR: create routine_change contributor
        normalized_impacts = {"routine_change": 1.0}
    else:
        normalized_impacts = {k: v / total_impact for k, v in raw_impacts.items()}
    
    # 3. Build contributors
    contributors = []
    min_impact = config.get("min_impact_to_show", 0.05)
    
    for contrib_id, impact in normalized_impacts.items():
        # Skip if impact too low (unless it's routine_change)
        if impact < min_impact and contrib_id != "routine_change":
            continue
            
        # Build contributor
        contributor = _build_contributor(contrib_id, impact, features, raw, config)
        if contributor:
            contributors.append(contributor)
    
    # 4. Sort contributors (deterministic)
    contributors = _sort_contributors(contributors)
    
    # 5. Assemble report
    report: ExplanationReport = {
        "risk_score": risk["risk_score"],
        "risk_prob": risk["risk_prob"],
        "decision": risk["decision"],
        "risk_level": risk["risk_level"],
        "top_contributors": contributors[:5],  # Top 5 for display
        "all_contributors": contributors,  # All for debugging
        "explain_version": "v1",
        "feature_version": features.get("feature_version", "unknown"),
        "model_version": risk.get("model_version")
    }
    
    # 6. Add threshold attribution (optional enhancement)
    _add_threshold_attribution(report, config)
    
    return report

def _add_threshold_attribution(report: ExplanationReport, config: Dict[str, Any]):
    """
    Add threshold attribution to top contributors when applicable.
    Shows which contributor triggered the decision.
    """
    decision = report["decision"]
    score = report["risk_score"]
    prob = report["risk_prob"]
    
    thresholds = config.get("thresholds", {})
    fail_score = thresholds.get("fail_score", 75)
    warn_score = thresholds.get("warn_score", 50)
    fail_prob = thresholds.get("fail_prob", 0.75)
    warn_prob = thresholds.get("warn_prob", 0.50)
    
    attribution = None
    
    if decision == "FAIL":
        if score >= fail_score:
            attribution = f"Triggered FAIL because score >= {fail_score} ({score})"
        elif prob >= fail_prob:
            attribution = f"Triggered FAIL because probability >= {fail_prob:.0%} ({prob:.0%})"
    elif decision == "WARN":
        if score >= warn_score:
            attribution = f"Triggered WARN because score >= {warn_score} ({score})"
        elif prob >= warn_prob:
            attribution = f"Triggered WARN because probability >= {warn_prob:.0%} ({prob:.0%})"
    
    # Add to top contributor details
    if attribution and report["top_contributors"]:
        top = report["top_contributors"][0]
        if "details" in top:
            top["details"].insert(0, f"⚠️ {attribution}")


def _build_contributor(contrib_id: str, 
                       impact: float, 
                       features: FeatureVector,
                       raw: RawSignals,
                       config: Dict[str, Any]) -> Contributor:
    """
    Build a single contributor with metrics, summary, and details.
    """
    # Prepare metrics dict
    metrics = {}
    evidence = []
    
    if contrib_id == "churn":
        metrics = {
            "churn_score": features.get("churn_score", 0.0),
            "churn_zscore": features.get("churn_zscore", 0.0),
            "total_churn": raw.get("total_churn", 0),
            "lines_added": raw.get("lines_added", 0),
            "lines_deleted": raw.get("lines_deleted", 0),
            "files_changed_count": len(raw.get("files_changed", [])),
            "top_file_churn_ratio": features.get("top_file_churn_ratio", 0.0),
            "files_p90": config.get("baselines", {}).get("files_changed_p90", 10)
        }
        summary, details = templates.render_churn(metrics, config)
        title = "High churn"
        
    elif contrib_id == "critical_path":
        # Extract matched patterns/files from config and raw
        crit_paths = config.get("critical_paths", {})
        matched_patterns = []
        matched_files = []
        
        for tier, patterns in crit_paths.items():
            # Defensive: Skip config keys that aren't lists (e.g. 'multiplier')
            if not isinstance(patterns, list):
                continue
                
            for pattern in patterns:
                for f in raw.get("files_changed", []):
                    if pattern in f:
                        matched_patterns.append(pattern)
                        matched_files.append(f)
        
        metrics = {
            "critical_path_score": features.get("critical_path_score", 0.0),
            "matched_patterns": list(set(matched_patterns)),
            "matched_files": list(set(matched_files))
        }
        summary, details = templates.render_critical_path(metrics, config)
        title = "Critical paths touched"
        
    elif contrib_id == "file_history":
        # TODO: Extract top risky files from features or raw
        # For now, placeholder
        metrics = {
            "file_historical_risk_score": features.get("file_historical_risk_score", 0.0),
            "top_risky_files": []  # Would come from feature computation
        }
        summary, details = templates.render_file_history(metrics, config)
        title = "Historically risky files"
        
    elif contrib_id == "dependency":
        metrics = {
            "dependency_risk_score": features.get("dependency_risk_score", 0.0),
            "downstream_count": len(raw.get("touched_services", [])),
            "tier0_services": raw.get("touched_services", [])[:3],  # Top 3
            "fanout": features.get("dependency_risk_score", 0.0)  # Proxy
        }
        summary, details = templates.render_dependency(metrics, config)
        title = "Blast radius"
        
    elif contrib_id == "history_bucket":
        metrics = {
            "historical_risk_score": features.get("historical_risk_score", 0.0),
            "bucket_rate": features.get("historical_risk_score", 0.0),  # Proxy
            "bucket_n": 50,  # Would come from bucket stats
            "bucket_id": "churn_high",  # Would come from bucketing logic
            "downweighted": False
        }
        summary, details = templates.render_history_bucket(metrics, config)
        title = "Historical pattern"
        
    elif contrib_id == "routine_change":
        metrics = {}
        summary, details = templates.render_routine_change(metrics, config)
        title = "Routine change"
        
    else:
        return None
    
    # Extract evidence from raw signals
    if raw.get("linked_issue_ids"):
        for issue_id in raw.get("linked_issue_ids", [])[:3]:
            evidence.append(f"Linked to issue #{issue_id}")
    
    contributor: Contributor = {
        "id": contrib_id,
        "title": title,
        "impact": round(impact, 4),
        "severity": severity.severity_from_impact(impact),
        "summary": summary,
        "details": details,
        "evidence": evidence,
        "metrics": metrics
    }
    
    return contributor

def _sort_contributors(contributors: List[Contributor]) -> List[Contributor]:
    """
    Sort contributors deterministically:
    1. By impact (descending)
    2. By priority (stable tie-break)
    3. By id (alphabetical)
    """
    def sort_key(c: Contributor):
        impact = c["impact"]
        contrib_id = c["id"]
        
        # Priority index (lower = higher priority)
        try:
            priority = CONTRIBUTOR_PRIORITY.index(contrib_id)
        except ValueError:
            priority = 999  # Unknown contributors go last
        
        # Sort by: -impact (desc), priority (asc), id (asc)
        return (-impact, priority, contrib_id)
    
    return sorted(contributors, key=sort_key)
