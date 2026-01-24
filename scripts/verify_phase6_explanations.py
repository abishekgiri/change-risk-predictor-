from compliancebot.ux.explain import ExplanationEngine
from compliancebot.ux.types import DecisionExplanation

def verify_explanations():
 print("Verifying Phase 6 Explanation Engine")
 print("====================================")
 
 engine = ExplanationEngine()
 
 # Case 1: High Churn Block
 print("\n1. Testing High Churn Scenario...")
 features_1 = {
 "total_churn": 600,
 "risky_files": [],
 "dependency_change": False
 }
 expl_1 = engine.generate(features_1, "BLOCK", 85)
 
 print(f"Summary: {expl_1.summary}")
 print(f"Top Factor: {expl_1.factors[0].label}")
 
 assert "BLOCKED" in expl_1.summary
 assert expl_1.factors[0].label == "Extremely High Code Churn"
 assert "Split this PR" in expl_1.factors[0].remediation[0]
 print("✅ High Churn Logic Verified")
 
 # Case 2: Hotspot & Dependency
 print("\n2. Testing Hotspot + Dependency Scenario...")
 features_2 = {
 "total_churn": 50,
 "risky_files": ["core/auth.py"],
 "dependency_change": True
 }
 expl_2 = engine.generate(features_2, "WARN", 65)
 
 # Should sort Hotspot (0.8) > Dependency (0.7)
 assert expl_2.factors[0].label == "Critical Hotspot Modified"
 assert expl_2.factors[1].label == "Dependency Manifest Modified"
 print(f"Narrative Preview:\n---\n{expl_2.narrative}\n---")
 print("✅ Ranking Logic Verified")
 
 # Case 3: Pass
 features_3 = {"total_churn": 10}
 expl_3 = engine.generate(features_3, "PASS", 10)
 assert "APPROVED" in expl_3.summary
 print("✅ Pass Logic Verified")
 
 print("\nExplanation Engine Verification Successful")

if __name__ == "__main__":
 verify_explanations()
