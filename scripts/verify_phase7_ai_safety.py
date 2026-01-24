from compliancebot.ai.safety_gate import AISafetyGate

def verify_safety_gate():
 print("Verifying Phase 7: AI Safety Gate")
 print("=================================")
 
 gate = AISafetyGate()
 
 # 1. Test Valid Explanation
 valid_ai = {
 "summary": "High risk detected.",
 "evidence_refs": ["score"],
 "disclaimer": "AI-generated."
 }
 auth_rec = {"decision": "BLOCK"}
 
 errors = gate.validate_explanation(valid_ai, auth_rec)
 assert len(errors) == 0
 print("✅ Valid Explanation Passed")
 
 # 2. Test Contradiction (Hallucination)
 bad_ai = {
 "summary": "This is approved.", # Contradicts BLOCK
 "evidence_refs": ["score"],
 "disclaimer": "AI-generated."
 }
 errors = gate.validate_explanation(bad_ai, auth_rec)
 assert len(errors) > 0
 assert "Contradiction" in errors[0]
 print("✅ Contradiction Caught")
 
 # 3. Test Unsafe Suggestion
 bad_sug = {
 "suggestions": [{
 "title": "Disable Security",
 "why": "Speed",
 "evidence_refs": ["foo"]
 }]
 }
 errors = gate.validate_suggestions(bad_sug)
 assert len(errors) > 0
 assert "Unsafe" in errors[0]
 print("✅ Unsafe Content Caught")

 # 4. Test Numeric Hallucination
 hallucinated_ai = {
 "summary": "Risk score is 999.", # 999 not in auth_rec
 "evidence_refs": ["score"],
 "disclaimer": "AI-generated."
 }
 # auth_rec has 80, not 999 (implicitly from previous test context or need new)
 auth_rec_nums = {"decision": "BLOCK", "risk_score": 80}
 
 errors = gate.validate_explanation(hallucinated_ai, auth_rec_nums)
 assert len(errors) > 0
 assert "Hallucinated Number: 999" in errors[0]
 print("✅ Numeric Hallucination Caught")

if __name__ == "__main__":
 verify_safety_gate()
