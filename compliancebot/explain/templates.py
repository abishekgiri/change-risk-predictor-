from typing import Tuple, List, Dict, Any

def render_churn(metrics: Dict[str, Any], config: Dict[str, Any] = None) -> Tuple[str, List[str]]:
    """
    Generate summary + details for churn contributor.
    
    Expected metrics:
    - churn_score: float
    - churn_zscore: float
    - total_churn: int
    - lines_added: int
    - lines_deleted: int
    - files_changed_count: int
    - top_file_churn_ratio: float
    - files_p90: int (optional)
    """
    z = metrics.get("churn_zscore", 0.0)
    total = metrics.get("total_churn", 0)
    added = metrics.get("lines_added", 0)
    deleted = metrics.get("lines_deleted", 0)
    files = metrics.get("files_changed_count", 0)
    top_ratio = metrics.get("top_file_churn_ratio", 0.0)
    p90 = metrics.get("files_p90")
    
    # Fix B: Guard z-score
    # Only show z-score if it's significant and stats are likely valid
    summary = f"High churn: {total} LOC"
    if abs(z) > 0.1 and total > 50:
        summary = f"High churn for this repo: {total} LOC (z={z:.2f})"
    
    details = [
        f"Total churn: {total} LOC (added {added}, deleted {deleted})",
        f"Files changed: {files}" + (f" (above p90={p90})" if p90 and files > p90 else ""),
        f"Concentration: top file = {int(top_ratio*100)}% of churn"
    ]
    
    return summary, details

def render_critical_path(metrics: Dict[str, Any], config: Dict[str, Any] = None) -> Tuple[str, List[str]]:
    """
    Generate summary + details for critical path contributor.
    
    Expected metrics:
    - critical_path_score: float
    - matched_patterns: List[str]
    - matched_files: List[str]
    """
    score = metrics.get("critical_path_score", 0.0)
    patterns = sorted(metrics.get("matched_patterns", [])) # Stable sort
    files = sorted(metrics.get("matched_files", []))[:5] # Top 5, sorted
    
    pattern_str = ", ".join(patterns) if patterns else "N/A"
    summary = f"Touched critical paths: {pattern_str}"
    
    details = [
        f"Critical path score: {score:.2f}",
        f"Matched patterns: {', '.join(patterns) if patterns else 'none'}",
        f"Files: {', '.join(files) if files else 'none'}"
    ]
    
    return summary, details

def render_file_history(metrics: Dict[str, Any], config: Dict[str, Any] = None) -> Tuple[str, List[str]]:
    """
    Generate summary + details for file historical risk contributor.
    
    Expected metrics:
    - file_historical_risk_score: float
    - top_risky_files: List[Dict] with keys: path, rate, n
    """
    score = metrics.get("file_historical_risk_score", 0.0)
    risky_files = metrics.get("top_risky_files", [])
    
    summary = "Touched historically incident-prone files"
    
    details = [f"File historical risk score: {score:.2f}"]
    
    # Sort by rate descending, then path for stability
    sorted_files = sorted(risky_files, key=lambda f: (-f.get("rate", 0), f.get("path", "")))
    
    for f in sorted_files[:3]: # Top 3
        path = f.get("path", "unknown")
        rate = f.get("rate", 0.0)
        n = f.get("n", 0)
        details.append(f"{path}: incident rate {rate:.1%} over n={n} changes")
    
    return summary, details

def render_dependency(metrics: Dict[str, Any], config: Dict[str, Any] = None) -> Tuple[str, List[str]]:
    """
    Generate summary + details for dependency/blast radius contributor.
    
    Expected metrics:
    - dependency_risk_score: float
    - downstream_count: int
    - tier0_services: List[str]
    - fanout: float (optional)
    """
    score = metrics.get("dependency_risk_score", 0.0)
    downstream = metrics.get("downstream_count", 0)
    tier0 = sorted(metrics.get("tier0_services", [])) # Stable sort
    fanout = metrics.get("fanout", 0.0)
    
    summary = f"Large blast radius: impacts {downstream} services"
    
    details = [
        f"Dependency risk score: {score:.2f}",
        f"Includes tier-0 services: {', '.join(tier0) if tier0 else 'none'}",
    ]
    
    if fanout > 0:
        details.append(f"Fanout score: {fanout:.2f}")

    # Fix B: Guard against 0 services
    if downstream == 0:
        summary = "Blast radius: unknown (no service graph match)"
    
    return summary, details

def render_history_bucket(metrics: Dict[str, Any], config: Dict[str, Any] = None) -> Tuple[str, List[str]]:
    """
    Generate summary + details for history bucket contributor.
    
    Expected metrics:
    - historical_risk_score: float
    - bucket_rate: float
    - bucket_n: int
    - bucket_id: str
    - downweighted: bool
    """
    score = metrics.get("historical_risk_score", 0.0)
    rate = metrics.get("bucket_rate", 0.0)
    n = metrics.get("bucket_n", 0)
    bucket_id = metrics.get("bucket_id", "unknown")
    downweighted = metrics.get("downweighted", False)
    
    summary = f"Similar changes failed {int(rate*100)}% historically"
    
    details = [
        f"Historical risk score: {score:.2f}",
        f"Bucket: {bucket_id} (n={n})"
    ]
    
    # Confidence hint
    min_samples = config.get("min_bucket_samples", 30) if config else 30
    if n < min_samples:
        details.append(f"History bucket downweighted (n={n} < {min_samples})")
    elif downweighted:
        details.append("Downweighted due to low sample size")
    
    return summary, details

def render_routine_change(metrics: Dict[str, Any], config: Dict[str, Any] = None) -> Tuple[str, List[str]]:
    """
    Generate summary + details for routine/safe change.
    
    Expected metrics: (minimal)
    """
    summary = "Routine change (no strong risk signals)"
    details = ["All risk indicators are below significance thresholds"]
    
    return summary, details

