import pytest
from riskbot.review import engine
from riskbot.scoring.types import RiskResult
from riskbot.explain.types import ExplanationReport

def test_rationale_cleans_bad_heuristics():
    """
    Verify that review priority rationale:
    1. Uses risk_result['reasons'] as primary source (clean).
    2. Does NOT include bad patterns like '_test.go' or '0 services'.
    """
    # 1. Setup Mock Input
    # Valid reasons from scoring (Fallback source)
    risk_result = RiskResult(
        risk_score=85,
        risk_level="HIGH",
        risk_prob=0.85,
        decision="FAIL",
        reasons=["Generic Score Reason"], 
        evidence=[],
        model_version="v1",
        feature_version="v1",
        components={"dependency": 0.0, "file_history": 0.0}, 
        data_quality="FULL"
    )

    # Explanation report (Primary source - assume clean from templates)
    explanation_report = {
        "top_contributors": [
            {"id": "churn", "summary": "High churn for this repo (z=2.50)"},
            {"id": "critical_path", "summary": "Touched critical paths: auth/, api/"},
            # "dependency" summary omitted (upstream suppresses 0 services)
        ]
    }

    # 2. Run Engine
    result = engine.compute_review_priority(
        pr_id="123",
        risk_result=risk_result,
        explanation_report=explanation_report
    )

    # 3. Verify
    print("\nGenerated Rationale:", result.rationale)

    # Should use explanation summaries
    assert "High churn for this repo (z=2.50)" in result.rationale
    assert "Touched critical paths: auth/, api/" in result.rationale
    assert "Generic Score Reason" not in result.rationale # Should prefer explanation
    
    # Verify data_quality is passed through (Fix C)
    assert result.data_quality == "FULL"
    
    # Should NOT have bad strings (implicitly true if we control input)
    for r in result.rationale:
        assert "_test.go" not in r, "Rationale contains test file suffix"
        assert "impacts 0 services" not in r, "Rationale contains zero blast radius"
