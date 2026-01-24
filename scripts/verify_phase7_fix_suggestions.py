import json
from compliancebot.ai.fix_suggester import AIFixSuggester
from compliancebot.ux.types import ExplanationFactor

# Mock Provider Injection to test Safety Filter
class UnsafeMockProvider:
 def generate_json(self, prompt, schema, model="mock"):
 return {
 "suggestions": [
 {
 "title": "Disable Security Checks", # Should be filtered
 "why": "To merge fast",
 "effort": "S",
 "evidence_refs": ["file:foo.py"]
 },
 {
 "title": "Add Unit Tests", # Should pass
 "why": "Good practice",
 "effort": "M",
 "evidence_refs": ["file:foo.py"]
 }
 ]
 }

def verify_suggestions():
 print("Verifying Phase 7: AI Fix Suggestions")
 print("=====================================")
 
 # 1. Standard Run
 suggester = AIFixSuggester()
 factors = [ExplanationFactor("Hotspot", "auth.py", 0.8, [])]
 
 result = suggester.propose({}, factors)
 print("Standard Result:", json.dumps(result, indent=2))
 
 assert "suggestions" in result
 assert len(result["suggestions"]) > 0
 assert "evidence_refs" in result["suggestions"][0]
 print("✅ Standard Suggestion Verified")
 
 # 2. Safety Filter Test
 print("\nTesting Safety Filter...")
 unsafe_suggester = AIFixSuggester()
 unsafe_suggester.provider = UnsafeMockProvider() # Inject malicious AI
 
 filtered_result = unsafe_suggester.propose({}, factors)
 print("Filtered Result:", json.dumps(filtered_result, indent=2))
 
 titles = [s["title"] for s in filtered_result["suggestions"]]
 assert "Disable Security Checks" not in titles
 assert "Add Unit Tests" in titles
 print("✅ Safety Filter Verified: Unsafe suggestion removed.")

if __name__ == "__main__":
 verify_suggestions()
