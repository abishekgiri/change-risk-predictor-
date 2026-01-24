import json
from compliancebot.ai.explain_writer import AIExplanationWriter
from compliancebot.ux.types import DecisionExplanation, ExplanationFactor

def verify_ai_explanations():
 print("Verifying Phase 7: AI Explanation Writer")
 print("========================================")
 
 # 1. Mock Authority Data (Phase 6)
 decision = {
 "decision": "BLOCK",
 "risk_score": 85,
 "features": {"churn": 600}
 }
 
 factors = [
 ExplanationFactor("High Churn", "600 lines", 0.9, ["Split PR"]),
 ExplanationFactor("Hotspot", "auth.py", 0.8, ["Add Tests"])
 ]
 
 auth_expl = DecisionExplanation(
 summary="Blocked due to churn",
 factors=factors,
 narrative="This PR is blocked because it touches 600 lines and modifies auth.py."
 )
 
 # 2. Run AI Writer
 writer = AIExplanationWriter()
 ai_json = writer.generate(decision, auth_expl)
 
 print("AI Output:")
 print(json.dumps(ai_json, indent=2))
 
 # 3. Verify Constraints
 assert ai_json["summary"] is not None
 assert "AI-generated" in ai_json["disclaimer"]
 assert "evidence_refs" in ai_json
 assert len(ai_json["evidence_refs"]) > 0
 
 print("\n✅ AI Explanation Schema Verified")
 print("✅ Evidence References Present")
 print("✅ Disclaimer Present")

if __name__ == "__main__":
 verify_ai_explanations()
