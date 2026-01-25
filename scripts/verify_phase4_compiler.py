import os
import shutil
import json
from compliancebot.policy_engine.builder import PolicyBuilder

SOURCE_DIR = "compliancebot/policies/dsl/test"
OUTPUT_DIR = "compliancebot/policies/compiled/test"

SAMPLE_DSL = """
policy SEC_PR_TEST {
 version: "1.0.0"
 name: "Test Policy"
 
 control TestControl {
 signals: [test.signal]
 }
 
 rules {
 when test.signal == true {
 enforce BLOCK
 message "Block message"
 }
 
 when test.signal == false {
 enforce WARN
 message "Warn message"
 }
 }
 
 compliance {
 TEST: "T1"
 }
}
"""

def verify_compiler():
    print("1. Setting up test environment...")
    if os.path.exists(SOURCE_DIR):
        shutil.rmtree(SOURCE_DIR)
    os.makedirs(SOURCE_DIR)
    
    with open(os.path.join(SOURCE_DIR, "test.dsl"), "w") as f:
        f.write(SAMPLE_DSL)
    
    print("2. Running PolicyBuilder...")
    builder = PolicyBuilder(SOURCE_DIR, OUTPUT_DIR)
    success = builder.build()
    
    if not success:
        print("Build failed")
        exit(1)
    
    print("3. Verifying Outputs...")
    
    # Check Manifest
    manifest_path = os.path.join(OUTPUT_DIR, "manifest.json")
    if not os.path.exists(manifest_path):
        print("Manifest not found")
        exit(1)
    
    with open(manifest_path) as f:
        manifest = json.load(f)
        print(f"Manifest found with keys: {manifest.keys()}")
        assert "SEC-PR-TEST" in manifest["policies"]
        rules = manifest["policies"]["SEC-PR-TEST"]["rules"]
        assert len(rules) == 2
        print(f"Found 2 rules in manifest: {rules}")
    
    # Check Rule 1 YAML
    r1_path = os.path.join(OUTPUT_DIR, "SEC-PR-TEST.R1.yaml")
    if not os.path.exists(r1_path):
        print(f"{r1_path} not found")
        exit(1)
    
    with open(r1_path) as f:
        r1 = json.load(f)
        print(f"Loaded R1: {r1['policy_id']}")
        assert r1['policy_id'] == "SEC-PR-TEST.R1"
        assert r1['enforcement']['result'] == "BLOCK"
        # Check Priority Logic
        assert r1['metadata']['priority'] == 120 # 100 + 20 (BLOCK) - 0 (index)
    
    # Check Rule 2 YAML
    r2_path = os.path.join(OUTPUT_DIR, "SEC-PR-TEST.R2.yaml")
    with open(r2_path) as f:
        r2 = json.load(f)
        print(f"Loaded R2: {r2['policy_id']}")
        assert r2['enforcement']['result'] == "WARN"
        assert r2['metadata']['priority'] == 109 # 100 + 10 (WARN) - 1 (index)

    print("\nVerification Successful: Compiler & Manifest Working")

if __name__ == "__main__":
    verify_compiler()

