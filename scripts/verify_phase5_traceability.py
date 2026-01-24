import os
import json
import shutil
from compliancebot.audit.traceability import TraceabilityInjector
from compliancebot.reports.generate import ReportGenerator
from compliancebot.engine import PolicyResult

COMPILED_DIR = "compliancebot/policies/compiled/mock"
BUNDLE_DIR = "audit_bundles/mock_report"

def verify_reports_traceability():
 print("Verifying Phase 5 Reports & Traceability")
 print("========================================")

 # 1. Setup Mock Compiled Policies
 os.makedirs(COMPILED_DIR, exist_ok=True)
 mock_policy = {
 "policy_id": "TEST.R1",
 "metadata": {
 "parent_policy": "TEST",
 "version": "1.2.3",
 "compliance": {"SOC2": "CC1.1"},
 "source_file": "test.dsl"
 }
 }
 with open(os.path.join(COMPILED_DIR, "TEST.R1.yaml"), 'w') as f:
 json.dump(mock_policy, f)
 
 # 2. Test Traceability Injection
 print("\n1. Testing Traceability Injection...")
 injector = TraceabilityInjector(COMPILED_DIR)
 
 raw_result = PolicyResult(
 policy_id="TEST.R1",
 name="Test Policy",
 status="BLOCK",
 triggered=True,
 violations=["violation 1"],
 evidence={},
 traceability={}
 )
 
 finding = injector.inject(raw_result)
 print(f"✅ Injected Finding: {finding.finding_id}")
 
 if finding.parent_policy != "TEST" or finding.compliance.get("SOC2") != "CC1.1":
 print("❌ Traceability data mismatch")
 exit(1)
 print("✅ Metadata verified correct")
 
 # 3. Test Report Generation
 print("\n2. Testing Report Generation...")
 if os.path.exists(BUNDLE_DIR):
 shutil.rmtree(BUNDLE_DIR)
 os.makedirs(BUNDLE_DIR, exist_ok=True)
 
 generator = ReportGenerator(BUNDLE_DIR)
 generator.generate_all([finding])
 
 reports = {
 "report.json": "JSON",
 "report.md": "Markdown", 
 "report.csv": "CSV"
 }
 
 for fname, desc in reports.items():
 path = os.path.join(BUNDLE_DIR, "reports", fname)
 if not os.path.exists(path):
 print(f"❌ Missing {desc} report: {path}")
 exit(1)
 print(f"✅ Found {desc} report")
 
 print("\nTraceability & Reports Verified Successfully")

if __name__ == "__main__":
 verify_reports_traceability()
