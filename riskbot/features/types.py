from typing import List, Dict, TypedDict, Literal, Optional, Union
from datetime import datetime

class RawSignals(TypedDict):
    """
    Contract for raw input signals from Ingestion/PRParser.
    Must contain only facts, no intelligence.
    """
    repo_slug: str
    entity_type: Literal["pr", "commit"]
    entity_id: str
    timestamp: Union[datetime, str]
    
    # Diff Stats (Required)
    files_changed: List[str]
    lines_added: int
    lines_deleted: int
    total_churn: int
    lines_deleted: int
    total_churn: int
    per_file_churn: Dict[str, int]
    commit_count: Optional[int]
    
    # Context (Optional/Derived)
    touched_services: List[str] # or blast_radius int if already computed
    linked_issue_ids: List[str]
    
    # Metadata
    author: Optional[str]
    branch: Optional[str]
    file_history: Optional[Dict[str, List[str]]] # filename -> list of commit dates

class FeatureVector(TypedDict):
    """
    Normalized feature vector for RiskScorer.
    All values should be 0-1 (except zscore).
    """
    feature_version: str # e.g. "v6"
    
    # Churn
    churn_score: float      # 0-1
    churn_zscore: float     # Unbounded (float)
    files_changed_score: float # 0-1
    top_file_churn_ratio: float # 0-1
    
    # Criticality
    critical_path_score: float # 0-1
    file_historical_risk_score: float # 0-1
    
    # Dependency
    dependency_risk_score: float # 0-1
    
    # History
    # History
    historical_risk_score: float # 0-1
    
    # Metadata (Passed through for Explainability)
    files_changed: Optional[List[str]]
    total_churn: Optional[int]
    commit_count: Optional[int]
    critical_subsystems: Optional[List[str]]
    is_tier_0: Optional[bool] # Hard gate flag
    test_files_count: Optional[int] # Track test file changes separately

# Explanation type
FeatureExplanation = List[str]
