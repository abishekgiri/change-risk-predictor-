#!/usr/bin/env python3
"""
Phase 3 Full Control Suite Verification

Tests all 5 Phase 3 controls with real fixtures.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def main():
    print("️ Phase 3: Full Control Suite Verification")
    print("=" * 50)
    
    passed = 0
    failed = 0
    
    # Test 1: Secrets Control
    print("\n1. Secret Scanner...")
    try:
        from compliancebot.controls.secrets import SecretsControl
        from compliancebot.controls.types import ControlContext
        
        control = SecretsControl()
        context = ControlContext(
            repo="test/repo", pr_number=1,
            diff={"config.py": '@@ -1,1 +1,2 @@\n+KEY="AKIAIOSFODNN7EXAMPLE"\n'},
            config={}, provider=None
        )
        result = control.execute(context)
        
        if result.signals.get("secrets.detected"):
            print(" ✓ Secrets control working")
            passed += 1
        else:
            print(" ❌ Secrets not detected")
            failed += 1
    except Exception as e:
        print(f" ❌ Error: {e}")
        failed += 1
    
    # Test 2: Privileged Change Control
    print("\n2. Privileged Code Detection...")
    try:
        from compliancebot.controls.privileged_change import PrivilegedChangeControl
        
        control = PrivilegedChangeControl()
        context = ControlContext(
            repo="test/repo", pr_number=1,
            diff={"auth/login.py": '@@ -1,1 +1,2 @@\n+# auth change\n'},
            config={"privileged_paths": {"auth": ["auth/*"]}},
            provider=None
        )
        result = control.execute(context)
        
        if result.signals.get("privileged.detected"):
            print(" ✓ Privileged change control working")
            passed += 1
        else:
            print(" ❌ Privileged path not detected")
            failed += 1
    except Exception as e:
        print(f" ❌ Error: {e}")
        failed += 1
    
    # Test 3: Approvals Control
    print("\n3. Approval Enforcement...")
    try:
        from compliancebot.controls.approvals import ApprovalsControl
        
        control = ApprovalsControl()
        context = ControlContext(
            repo="test/repo", pr_number=1,
            diff={}, config={}, provider=None
        )
        result = control.execute(context)
        
        # Should pass when no requirements
        if result.signals.get("approvals.satisfied") == True:
            print(" ✓ Approvals control working")
            passed += 1
        else:
            print(" ❌ Approvals logic error")
            failed += 1
    except Exception as e:
        print(f" ❌ Error: {e}")
        failed += 1
    
    # Test 4: License Control
    print("\n4. License Scanner...")
    try:
        from compliancebot.controls.licenses import LicensesControl
        
        control = LicensesControl()
        context = ControlContext(
            repo="test/repo", pr_number=1,
            diff={}, config={}, provider=None
        )
        result = control.execute(context)
        
        # Should have signals even if no licenses scanned
        if "licenses.scanned" in result.signals:
            print(" ✓ License control working")
            passed += 1
        else:
            print(" ❌ License signals missing")
            failed += 1
    except Exception as e:
        print(f" ❌ Error: {e}")
        failed += 1
    
    # Test 5: Environment Boundary Control
    print("\n5. Environment Boundaries...")
    try:
        from compliancebot.controls.env_boundary import EnvironmentBoundaryControl
        
        control = EnvironmentBoundaryControl()
        context = ControlContext(
            repo="test/repo", pr_number=1,
            diff={}, config={}, provider=None
        )
        result = control.execute(context)
        
        # Should have signals even if not configured
        if "env_boundary.configured" in result.signals:
            print(" ✓ Environment boundary control working")
            passed += 1
        else:
            print(" ❌ Environment signals missing")
            failed += 1
    except Exception as e:
        print(f" ❌ Error: {e}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n✅ All Phase 3 controls VERIFIED")
        return 0
    else:
        print(f"\n❌ {failed} control(s) failed verification")
        return 1

if __name__ == "__main__":
    sys.exit(main())

