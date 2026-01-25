from typing import Dict, Any, List
from compliancebot.config import SEVERITY_THRESHOLD_HIGH
from compliancebot.features.types import FeatureVector
from compliancebot.scoring.types import RiskResult
from compliancebot.scoring import baseline, thresholds, calibration, model

class RiskScorer:
    """
    Risk Scorer V2 (Phase 8: Product Build).
    Orchestrates Baseline, Calibration, and Thresholds.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.calibrator = calibration.Calibrator(self.config)
        self.model = model.RiskModel() # Attempts to load model

    def calculate_score(self, features: FeatureVector, evidence: List[str] = None) -> RiskResult:
        """
        Calculate strict RiskResult from FeatureVector.
        """
        evidence = evidence or []
        
        # 0. Version Gate
        if features.get("feature_version") != "v6":
            print(f"Warning: Feature version mismatch. Expected v6, got {features.get('feature_version')}")

        # 1. Compute Raw Score
        raw_score = None
        model_version = "baseline-v1"
        reasons = []
        components = {}
        
        # 1.5 Tier-0 Hard Gate
        if features.get("is_tier_0") and features.get("files_changed"):
            # FAIL immediately if Tier-0 path is touched and it's not empty
            return {
                "risk_score": 100,
                "risk_prob": 1.0,
                "risk_level": "CRITICAL",
                "decision": "FAIL",
                "reasons": [f"Touches Tier-0 critical path: {features.get('critical_subsystems', ['unknown'])[0]}", "Tier-0 changes require mandatory blocking review"],
                "evidence": evidence,
                "model_version": "tier0-gate",
                "feature_version": features.get("feature_version"),
                "components": {},
                "data_quality": "FULL"
            }

        # 2. Additive Risk Scoring + Impact Bonus
        # Base weights summing to 100 (if all scores are 1.0)
        # Weights: Churn=40, Crit=30, Dep=20, Hist=10
        
        churn_points = features.get("churn_score", 0.0) * 40
        crit_points = features.get("critical_path_score", 0.0) * 30
        dep_points = features.get("dependency_risk_score", 0.0) * 20
        hist_points = features.get("file_historical_risk_score", 0.0) * 10
        
        base_score = churn_points + crit_points + dep_points + hist_points
        
        # Impact Bonus (Capped)
        bonus = 0.0
        
        # Bonus 1: Critical Component Touched (Tiered)
        # Check files against tiered config
        crit_config = self.config.get("critical_paths", {})
        bonuses = crit_config.get("bonuses", {"core": 25, "high": 15, "medium": 10, "low": 5})
        
        max_crit_bonus = 0
        matched_tier = None
        
        files_changed = features.get("files_changed", [])
        
        # Per-file analysis to correctly handle overrides (e.g. testdata inside high path)
        for f in files_changed:
            current_file_tier = None
            current_file_bonus = 0
            
            # 1. Check Low (Test) First - acts as override/filter
            is_low = False
            for p in crit_config.get("low", []):
                if p in f:
                    is_low = True
                    current_file_tier = "low"
                    current_file_bonus = bonuses["low"]
                    break
            
            # If Low, stop matching for this file (it's verified test code)
            if is_low:
                if current_file_bonus > max_crit_bonus:
                    max_crit_bonus = current_file_bonus
                # Only update global tier if we haven't found a higher one yet
                if matched_tier not in ["core", "high", "medium"]:
                    matched_tier = "low"
                continue

            # 2. Check Core
            for p in crit_config.get("core", []):
                if p in f:
                    current_file_tier = "core"
                    current_file_bonus = bonuses["core"]
                    break
            
            # 3. Check High (if not core)
            if not current_file_tier:
                for p in crit_config.get("high", []):
                    if p in f:
                        current_file_tier = "high"
                        current_file_bonus = bonuses["high"]
                        break
            
            # 4. Check Medium (if not high)
            if not current_file_tier:
                for p in crit_config.get("medium", []):
                    if p in f:
                        current_file_tier = "medium"
                        current_file_bonus = bonuses["medium"]
                        break
            
            # Update global max
            if current_file_bonus > max_crit_bonus:
                max_crit_bonus = current_file_bonus
                matched_tier = current_file_tier
        
        bonus += max_crit_bonus
        
        # Bonus 2: Broad Dependency Impact
        if features.get("dependency_risk_score", 0.0) > 0.6:
            bonus += 10
        
        # Bonus 3: Dangerous History
        if features.get("file_historical_risk_score", 0.0) > 0.7:
            bonus += 10
        
        raw_score = base_score + bonus
        
        # Soft cap at 100 and Round
        raw_score = min(raw_score, 100)
        raw_score = round(raw_score)
        
        # Components for explanation
        components = {
            "churn": features.get("churn_score", 0.0),
            "total_churn": features.get("total_churn", 0),
            "criticality": features.get("critical_path_score", 0.0),
            "dependency": features.get("dependency_risk_score", 0.0),
            "file_history": features.get("file_historical_risk_score", 0.0),
            "history": features.get("historical_risk_score", 0.0),
            "base_score": round(base_score, 1),
            "bonus_score": bonus,
            "matched_tier": matched_tier
        }
        
        # 2. Calibrate Probability
        prob = self.calibrator.calibrate(raw_score)
        
        # 3. Decision Logic (New Thresholds)
        decision = "PASS"
        level = "LOW"
        
        if raw_score >= 50:
            decision = "FAIL"
            level = "HIGH"
        elif raw_score >= 25:
            decision = "WARN"
            level = "MEDIUM"
        
        # 3.5 Specific Safety Override if not already FAIL
        if decision != "FAIL":
            # Safety: If High Criticality AND Moderate Dependency/History, Upgrade to WARN
            if features.get("critical_path_score", 0.0) > 0.8 and raw_score > 15:
                decision = "WARN"
                level = "MEDIUM"
                reasons.append("Upgraded to WARN: High Criticality check")
        
        # 3. Generate reasons from components
        reasons = []
        
        # Churn-based reasons (UX FIX)
        tc = components.get("total_churn", 0)
        if tc >= 1500:
            reasons.append(f"Extreme Churn: {tc} LOC (Capped)")
        elif tc >= 300:
            reasons.append(f"High Churn: {tc} LOC")
        elif tc >= 50:
            reasons.append(f"Moderate Churn: {tc} LOC")
        
        # Critical path reasons (Impact)
        if matched_tier:
            reasons.append(f"Touches {matched_tier} critical subsystem (+{max_crit_bonus} bonus)")
        
        if components["criticality"] >= 0.5 and not matched_tier:
            reasons.append("Touches critical paths (auth/, payments/, or core infrastructure)")
        elif components["criticality"] >= 0.3:
            reasons.append("Affects important system components")
        
        # 2. Add Test changes reason (Fix B: Separated)
        test_count = features.get("test_files_count", 0)
        if test_count > 0:
            reasons.append(f"Includes test changes: {test_count} files")
        
        # File history reasons
        if components["file_history"] >= 0.4:
            reasons.append("Modifies historically incident-prone files")
        elif components["file_history"] >= 0.2:
            reasons.append("Touches files with some incident history")
        
        # Dependency reasons (Fix C: Blast Radius)
        if components["dependency"] >= 0.5:
            reasons.append("Large blast radius - impacts multiple services")
        elif components["dependency"] >= 0.2:
            reasons.append("Affects shared dependencies or downstream services")
        
        # Historical pattern reasons
        if components["history"] >= 0.3:
            reasons.append("Similar changes have caused incidents historically")
        
        # If no specific reasons but score is elevated
        if not reasons and raw_score >= 40:
            reasons.append("Elevated risk based on combined factors")
        
        # Low risk explanation
        if not reasons and raw_score < 20:
            reasons.append("Routine change with minimal risk signals")
        
        # 3.5. Populate evidence from features (file-specific details)
        evidence_items = []
        if features.get("files_changed"):
            files = features.get("files_changed", [])
            if len(files) > 0:
                evidence_items.append(f"Files changed: {len(files)}")
                if len(files) <= 5:
                    for f in files[:5]:
                        evidence_items.append(f"Modified: {f}")
        
        if features.get("total_churn", 0) > 0:
            evidence_items.append(f"Total churn: {features.get('total_churn')} LOC")
        
        if features.get("commit_count", 0) > 0:
            evidence_items.append(f"Commits: {features.get('commit_count')}")
        
        all_evidence = evidence_items + (evidence or [])
        
        # 3.6. Determine data quality
        data_quality = "FULL"
        if raw_score <= 1 and len(reasons) == 0:
            data_quality = "FALLBACK"
        elif not features.get("files_changed") or len(features.get("files_changed", [])) == 0:
            data_quality = "PARTIAL"
            evidence_items.append("No files fetched (churn=0.0)")
        
        # 4. Construct Result
        result: RiskResult = {
            "risk_score": raw_score,
            "risk_prob": prob,
            "risk_level": level,
            "decision": decision,
            "reasons": reasons[:5],
            "evidence": all_evidence[:5],
            "model_version": model_version,
            "feature_version": features.get("feature_version", "unknown"),
            "components": components,
            "data_quality": data_quality
        }
        
        return result
    
    def calculate_score_with_explanation(self, features: FeatureVector, raw: Any = None, evidence: List[str] = None):
        """
        Calculate score and generate explanation report.
        """
        from compliancebot.explain import explainer as exp
        
        # Calculate risk
        result = self.calculate_score(features, evidence)
        
        # Generate explanation
        raw_signals = raw or {}
        report = exp.explain(raw_signals, features, result, self.config)
        
        return result, report


if __name__ == "__main__":
    # Test
    scorer = RiskScorer()
    
    # Mock Risky FeatureVector
    risky: FeatureVector = {
        "feature_version": "v6",
        "churn_score": 0.9,
        "churn_zscore": 2.5,
        "files_changed_score": 0.8,
        "top_file_churn_ratio": 0.2,
        "critical_path_score": 1.0,
        "file_historical_risk_score": 0.0,
        "dependency_risk_score": 0.8,
        "historical_risk_score": 0.4
    }
    print("Risky:", scorer.calculate_score(risky))

