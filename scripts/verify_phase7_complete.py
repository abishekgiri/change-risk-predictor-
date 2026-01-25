import os
import json
# Simulate Phase 6 inputs
from compliancebot.ux.types import DecisionExplanation, ExplanationFactor
from compliancebot.ai.explain_writer import AIExplanationWriter
from compliancebot.ai.fix_suggester import AIFixSuggester
from compliancebot.ai.safety_gate import AISafetyGate

def verify_full_phase7():
    print("Verifying Phase 7 End-to-End Pipeline")
    print("=====================================")
    
    # 1. Setup Phase 6 Context (Authority)
    decision = {"decision": "BLOCK", "risk_score": 80}
    # Match values in MockProvider to pass strict fact check
    factors = [
        ExplanationFactor("Critical Churn", "Change > 500 lines", 0.9, ["Split it"]),
        ExplanationFactor("Hotspot", "Hotspot modified", 0.8, [])
    ]
    auth_expl = DecisionExplanation("Blocked", factors, "Narrative")
    
    # 2. Pipeline: AI Explanation
    print("\n[1/3] Generating AI Explanation...")
    writer = AIExplanationWriter()
    ai_expl = writer.generate(decision, auth_expl)
    
    # 3. Pipeline: Safety Check
    # 3. Pipeline: Safety Check
    gate = AISafetyGate()
    # Combine decision and explanation into one context for validation
    validation_context = decision.copy()
    validation_context["explanation_factors"] = [f.evidence for f in auth_expl.factors]
    
    errors = gate.validate_explanation(ai_expl, validation_context)
    if errors:
        print(f"❌ Safety Gate FAILED: {errors}")
        exit(1)
    print("✅ AI Explanation Generated & Safe")
    
    # 4. Pipeline: Suggestions
    print("\n[2/3] Generating Fix Suggestions...")
    suggester = AIFixSuggester()
    ai_fixes = suggester.propose(decision, factors)
    
    errors = gate.validate_suggestions(ai_fixes)
    if errors:
        print(f"❌ Safety Gate FAILED: {errors}")
        exit(1)
    print("✅ Fix Suggestions Generated & Safe")
    
    # 5. Persist Artifacts (Enterprise Requirement)
    print("\n[3/3] Persisting Artifacts to Bundle...")
    # Mock efficient bundle path
    bundle_dir = "audit_bundles/mock_phase7/ai"
    os.makedirs(bundle_dir, exist_ok=True)
    
    with open(f"{bundle_dir}/ai_explanation.v1.json", "w") as f:
        json.dump(ai_expl, f, indent=2)
    
    with open(f"{bundle_dir}/fix_suggestions.v1.json", "w") as f:
        json.dump(ai_fixes, f, indent=2)
    
    # Write Safety Report
    with open(f"{bundle_dir}/ai_safety_report.json", "w") as f:
        json.dump({"status": "PASS", "checks": ["fact_consistency", "safety_filter"]}, f, indent=2)
    
    print(f"✅ Artifacts written to {bundle_dir}/")
    
    # 6. Verify Persistence
    assert os.path.exists(f"{bundle_dir}/ai_explanation.v1.json")
    assert os.path.exists(f"{bundle_dir}/fix_suggestions.v1.json")

    print("\n Phase 7 Pipeline Verified")

if __name__ == "__main__":
    verify_full_phase7()

