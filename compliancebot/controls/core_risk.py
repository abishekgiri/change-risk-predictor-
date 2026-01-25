from compliancebot.scoring.risk_score import RiskScorer
from compliancebot.features.feature_store import FeatureStore
from typing import Dict, Any

class CoreRiskControl:
    """
    Wraps the Phase 1 Risk Scoring Engine as a deterministic control.
    Output is now treated as 'Severity' signal, not just risk.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scorer = RiskScorer(config)
        self.feature_store = FeatureStore(config)
    
    def evaluate(self, raw_signals: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate core risk controls.
        Returns normalized control output.
        """
        features, explanations = self.feature_store.build_features(raw_signals)
        score_result = self.scorer.calculate_score(features, evidence=explanations)
        
        # Map legacy result to Control Signal format
        return {
            "control_type": "core_risk_scoring",
            "violation_severity": score_result["risk_score"],
            "severity_level": score_result["risk_level"], # HIGH, MEDIUM, LOW
            "control_result": self._map_decision(score_result["decision"]),
            "signals": {
                "churn": score_result["components"].get("total_churn", 0),
                "criticality": score_result["components"].get("criticality", 0.0),
                "history": score_result["components"].get("history", 0.0),
            },
            "violations": score_result["reasons"],
            "evidence": score_result["evidence"],
            "raw_features": features
        }
    
    def _map_decision(self, legacy_decision: str) -> str:
        """Map PASS/WARN/FAIL to COMPLIANT/WARN/BLOCK"""
        mapping = {
            "FAIL": "BLOCK",
            "WARN": "WARN",
            "PASS": "COMPLIANT"
        }
        return mapping.get(legacy_decision, "COMPLIANT")

