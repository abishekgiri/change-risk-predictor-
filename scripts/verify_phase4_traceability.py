import sys
from compliancebot.engine import ComplianceEngine
from compliancebot.policies.types import Policy, ControlSignal, EnforcementConfig

# Mock Policy with Metadata
MOCK_POLICY = Policy(
 policy_id="SEC-PR-002.R1",
 name="Secret Scanner Rule 1",
 controls=[
 ControlSignal(signal="test.signal", operator="==", value=True)
 ],
 enforcement=EnforcementConfig(result="BLOCK"),
 metadata={
 "parent_policy": "SEC-PR-002",
 "rule_id": "R1",
 "version": "2.0.0",
 "effective_date": "2026-01-01",
 "compliance": {"SOC2": "CC6.1"}
 }
)

def verify_traceability():
 print("1. Setup Engine with Mock Policy...")
 # Initialize Engine (config ignored for this test)
 engine = ComplianceEngine({})
 
 # Inject Mock Policy directly (bypassing loader for unit test)
 engine.policies = [MOCK_POLICY]
 
 print("2. Evaluate with Signals...")
 signals = {
 "test.signal": True, # Trigger the rule
 # Add required Core Risk signals to satisfy initial checks
 "total_churn": 10,
 "additions": 5,
 "deletions": 5,
 "files_changed": [], 
 "per_file_churn": []
 }
 result = engine.evaluate(signals)
 
 if not result.results:
 print("No results returned")
 exit(1)
 
 p_res = result.results[0]
 print(f"✅ Policy Evaluated: {p_res.policy_id}")
 
 print("3. Verify Traceability Injection...")
 trace = p_res.traceability
 
 if not trace:
 print("Traceability metadata missing")
 exit(1)
 
 print(f"Captured Metadata: {trace}")
 
 # Assertions
 assert trace["parent_policy"] == "SEC-PR-002"
 assert trace["version"] == "2.0.0"
 assert trace["compliance"]["SOC2"] == "CC6.1"
 assert trace["effective_date"] == "2026-01-01"
 
 print("\nEvidence Traceability Verified: Metadata correctly injected into findings.")

if __name__ == "__main__":
 verify_traceability()
