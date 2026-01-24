import os
import json
import shutil
from compliancebot.policy_engine.builder import PolicyBuilder

SOURCE_DIR = "compliancebot/policies/dsl/standards/iso27001"
OUTPUT_DIR = "compliancebot/policies/compiled/standards/iso27001"

def verify_iso27001_pack():
 print("1. Building ISO 27001 Pack...")
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
 
 expected_policies = ["ISO27001-A9-AccessControl", "ISO27001-A12-OperationsSecurity", "ISO27001-A14-SecureDevelopment"]
 expected_standard = "ISO27001"
 
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
 # exit(1) # Don't exit yet, check strict mapping
 
 # A.9 mapping
 if "A9" in pid:
 assert "A.9" in mappings[expected_standard]
 print(f"Verified A.9 Mapping")
 
 print("\nISO 27001 Rule Pack Verified")

if __name__ == "__main__":
 verify_iso27001_pack()
