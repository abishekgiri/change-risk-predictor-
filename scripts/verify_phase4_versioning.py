import os
import json
import shutil
from compliancebot.policy_engine.builder import PolicyBuilder

SOURCE_DIR = "compliancebot/policies/dsl/test_versioning"
OUTPUT_DIR = "compliancebot/policies/compiled/test_versioning"

# Define two versions of the same policy
POLICY_V1 = """
policy TEST_Policy {
 version: "1.0.0"
 name: "Test Policy V1"
 effective_date: "2025-01-01"
 
 rules {
 when test.signal == true { enforce WARN }
 }
}
"""

POLICY_V2 = """
policy TEST_Policy {
 version: "2.0.0"
 name: "Test Policy V2"
 effective_date: "2026-01-01"
 supersedes: "1.0.0"
 
 rules {
 when test.signal == true { enforce BLOCK } # V2 is stricter
 }
}
"""

def verify_versioning():
 print("1. Setting up Test Environment...")
 if os.path.exists(SOURCE_DIR): shutil.rmtree(SOURCE_DIR)
 os.makedirs(SOURCE_DIR)

 # Step 1: Build Version 1
 print("2. Building Version 1.0.0...")
 with open(os.path.join(SOURCE_DIR, "policy.dsl"), "w") as f:
 f.write(POLICY_V1)
 
 builder = PolicyBuilder(SOURCE_DIR, OUTPUT_DIR)
 builder.build()
 
 # Verify V1 manifest
 with open(os.path.join(OUTPUT_DIR, "manifest.json")) as f:
 manifest = json.load(f)
 assert manifest["policies"]["TEST-Policy"]["version"] == "1.0.0"
 print("✅ Manifest confirms V1.0.0 active")

 # Step 2: Build Version 2 (In a real system, these might exist in parallel folders or be tagged git refs)
 # For Phase 4 MVP, the manifest tracks the *current* state of the repo.
 # To demonstrate pinning, we need to show that the METADATA carries the version,
 # and a hypothetical loader could choose based on it if we had multiple compiled files.
 
 print("3. Building Version 2.0.0...")
 with open(os.path.join(SOURCE_DIR, "policy.dsl"), "w") as f:
 f.write(POLICY_V2)
 
 builder.build()
 
 # Reload Manifest
 with open(os.path.join(OUTPUT_DIR, "manifest.json")) as f:
 manifest = json.load(f)
 v2_version = manifest["policies"]["TEST-Policy"]["version"]
 assert v2_version == "2.0.0"
 print(f"✅ Manifest updated to V{v2_version}")
 
 # Verify Metadata in Compiled Rule
 rule_id = manifest["policies"]["TEST-Policy"]["rules"][0]
 rule_path = os.path.join(OUTPUT_DIR, f"{rule_id}.yaml")
 
 with open(rule_path) as f:
 rule = json.load(f)
 meta = rule["metadata"]
 
 print(f"✅ Rule Metadata Version: {meta['version']}")
 print(f"✅ Rule Metadata Effective: {meta['effective_date']}")
 print(f"✅ Rule Metadata Supersedes: {meta['supersedes']}")
 
 assert meta['version'] == "2.0.0"
 assert meta['effective_date'] == "2026-01-01"
 assert meta['supersedes'] == "1.0.0"
 
 print("\n✅ Policy Versioning & Metadata Verified")

if __name__ == "__main__":
 verify_versioning()
