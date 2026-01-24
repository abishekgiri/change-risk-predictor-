import os
import json
import shutil
from compliancebot.policy_engine.builder import PolicyBuilder

SOURCE_DIR = "compliancebot/policies/dsl/company/acme"
OUTPUT_DIR = "compliancebot/policies/compiled/company/acme"

def verify_custom_pack():
 print("1. Building Acme Corp Pack...")
 if os.path.exists(OUTPUT_DIR):
 shutil.rmtree(OUTPUT_DIR)
 
 builder = PolicyBuilder(SOURCE_DIR, OUTPUT_DIR)
 success = builder.build()
 
 if not success:
 print("❌ Build failed")
 exit(1)
 
 print("2. Verifying Manifest and Rules...")
 manifest_path = os.path.join(OUTPUT_DIR, "manifest.json")
 
 with open(manifest_path) as f:
 manifest = json.load(f)
 
 if "ACME-Sec-001" not in manifest["policies"]:
 print("❌ Missing ACME policy in manifest")
 exit(1)
 
 print("✅ Found ACME-Sec-001 in manifest")
 
 rules = manifest["policies"]["ACME-Sec-001"]["rules"]
 print(f"✅ Generated {len(rules)} rules: {rules}")
 
 # Check Stricter Approval Rule
 r1_path = os.path.join(OUTPUT_DIR, f"{rules[0]}.yaml")
 with open(r1_path) as f:
 r1 = json.load(f)
 print(f"✅ Loaded Rule 1: {r1['policy_id']}")
 # Require >= 2 -> when count < 2 -> BLOCK
 assert r1['enforcement']['result'] == "BLOCK"
 # Check priority (BLOCK base is 120)
 assert r1['metadata']['priority'] == 120
 
 print("\n✅ Custom Policy Pack Verified")

if __name__ == "__main__":
 verify_custom_pack()
