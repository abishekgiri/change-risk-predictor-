import os
import json
import shutil
from compliancebot.policy_engine.builder import PolicyBuilder

SOURCE_DIR = "compliancebot/policies/dsl/standards/hipaa"
OUTPUT_DIR = "compliancebot/policies/compiled/standards/hipaa"

def verify_hipaa_pack():
 print("1. Building HIPAA Pack...")
 if os.path.exists(OUTPUT_DIR):
 shutil.rmtree(OUTPUT_DIR)
 
 builder = PolicyBuilder(SOURCE_DIR, OUTPUT_DIR)
 success = builder.build()
 
 if not success:
 print("Build failed")
 exit(1)
 
 print("2. Verifying Compliance Mappings...")
 manifest_path = os.path.join(OUTPUT_DIR, "manifest.json")
 
 with open(manifest_path) as f:
 manifest = json.load(f)
 
 expected_policies = ["HIPAA-164-312-a-AccessControl", "HIPAA-164-312-b-AuditControls", "HIPAA-164-312-c-Integrity"]
 expected_standard = "HIPAA"
 
 for pid in expected_policies:
 if pid not in manifest["policies"]:
 print(f"Missing policy in manifest: {pid}")
 exit(1)
 print(f"Found {pid} in manifest")
 
 # Check first rule of each
 rule_id = manifest["policies"][pid]["rules"][0]
 rule_path = os.path.join(OUTPUT_DIR, f"{rule_id}.yaml")
 
 with open(rule_path) as f:
 yaml_content = json.load(f)
 
 mappings = yaml_content["metadata"].get("compliance", {})
 if expected_standard not in mappings:
 print(f"Missing {expected_standard} compliance mapping in {rule_id}")
 exit(1)
 
 print(f"Verified {rule_id}: {mappings[expected_standard]}")

 print("\nHIPAA Rule Pack Verified")

if __name__ == "__main__":
 verify_hipaa_pack()
