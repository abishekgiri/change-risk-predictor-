import os
import json
import uuid
import shutil
from compliancebot.evidence.bundler import EvidenceBundler
from compliancebot.audit.types import TraceableFinding

REPO = "abishekgiri/change-risk-predictor"
PR = 999
AUDIT_ID = str(uuid.uuid4())
BUNDLE_ROOT = "audit_bundles"

def verify_bundle():
    print("Verifying Phase 5 Evidence Bundling")
    print("===================================")
    
    # Clean previous run
    if os.path.exists(BUNDLE_ROOT):
        shutil.rmtree(BUNDLE_ROOT)
    
    bundler = EvidenceBundler(REPO, PR, AUDIT_ID)
    print(f"Bundle Path: {bundler.bundle_path}")
    
    # 1. Dummy Inputs
    inputs = {"meta": "data"}
    diff_text = """diff --git a/main.py b/main.py
index 83db48f..f735c32 100644
--- a/main.py
+++ b/main.py
@@ -10,3 +10,3 @@
- print("Hello")
+ print("World")
"""
    policies = {"SEC-PR-001": "v1.0"}
    
    findings = [
        TraceableFinding(
            finding_id="f1", fingerprint="hash1", message="Bad code", severity="HIGH", 
            policy_id="P1", parent_policy="P", rule_id="R1", policy_version="1.0",
            compliance={}
        )
    ]

    # 2. Create Bundle
    print("\n1. Creating Bundle...")
    manifest_hash = bundler.create_bundle(inputs, findings, diff_text, policies)
    print(f"✅ Bundle Created. Manifest Hash: {manifest_hash}")
    
    # 3. Verify Files Exist
    expected_files = [
        "manifest.json",
        "inputs/pr_metadata.json",
        "findings.json",
        "policies_used.json",
        "artifacts/diff.patch",
        "artifacts/snippets/hash1_0.txt" # Snippet generated for finding
    ]
    
    for f in expected_files:
        path = os.path.join(bundler.bundle_path, f)
        if not os.path.exists(path):
            print(f"❌ Missing file: {f}")
            exit(1)
        print(f"✅ Found file: {f}")
    
    # 4. Verify Integrity (Hash Check)
    print("\n2. Verifying Integrity...")
    with open(os.path.join(bundler.bundle_path, "manifest.json")) as f:
        manifest = json.load(f)
    
    # Check one file
    snippet_rel_path = "artifacts/snippets/hash1_0.txt"
    listed_hash = manifest[snippet_rel_path]
    computed_hash = bundler._compute_file_hash(snippet_rel_path)
    
    if listed_hash != computed_hash:
        print(f"❌ Hash Mismatch for {snippet_rel_path}")
        exit(1)
    
    print(f"✅ Hash Match Verified: {listed_hash}")
    print("\nEvidence Bundle Verification Successful")

if __name__ == "__main__":
    verify_bundle()
