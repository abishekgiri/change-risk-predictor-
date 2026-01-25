import subprocess
import os
import shutil

def verify_full_ux():
    print("Verifying Phase 6 Enterprise UX End-to-End")
    print("==========================================")
    
    # 1. Run CLI (using pick-hard demo mode to trigger logic)
    # Using 'huge_churn' mode to trigger Churn Explanation
    cmd = [
        "python3", "-m", "compliancebot.cli", "pick-hard", 
        "--repo", "prometheus/prometheus", 
        "--mode", "huge_churn"
    ]
    
    print("Running CLI:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    output = result.stdout
    print("\n--- CLI Output Snippet ---")
    print(output[-1000:]) # Show last 1k chars
    print("--------------------------")
    
    # 2. Check for UI Elements
    checks = [
        " DECISION EXPLANATION",
        "Recommended Actions:",
        "Audit Bundle & Reports:",
        "Audit Logged:"
    ]
    
    failed = False
    for check in checks:
        if check in output:
            print(f"✅ Found UI Element: '{check}'")
        else:
            print(f"❌ Missing UI Element: '{check}'")
            failed = True
    
    
    # 3. Check specific explanation logic (High Churn)
    if "High Code Churn" in output or "Extremely High Code Churn" in output:
        print("✅ Correct Diagnosis (Churn Detected)")
    
        # INVARIANT 1: High Churn Factor must NOT result in Score 0 or APPROVED
        if "Risk Score: 0/100" in output:
            print("❌ INVARIANT VIOLATION: High Churn Factor found but Risk Score is 0!")
            failed = True
        if "Deployment APPROVED" in output and "Threshold: 500" in output:
            print("❌ INVARIANT VIOLATION: High Churn Factor found but Decision is APPROVED!")
            failed = True
    else:
        print("❌ Failed to diagnose Churn")
        failed = True
    
    if failed:
        print("\n❌ Verification FAILED")
        exit(1)
    
    print("\n✅ Phase 6 Complete Verification Successful")

if __name__ == "__main__":
    verify_full_ux()

