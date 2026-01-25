import os
import sys
import shutil
from compliancebot.engine import ComplianceEngine
from compliancebot.policy_engine.builder import PolicyBuilder

# Paths
DSL_ROOT = "compliancebot/policies/dsl"
COMPILED_ROOT = "compliancebot/policies/compiled"

def verify_integration():
    print("Starting Phase 4 End-to-End Verification")
    
    # 1. Compile Everything to Ensure Fresh State
    print("\n1. Compiling All Rule Packs...")
    
    packs = [
        ("standards/soc2", "standards/soc2"),
        ("standards/iso27001", "standards/iso27001"),
        ("standards/hipaa", "standards/hipaa"),
        ("company/acme", "company/acme")
    ]
    
    for src, dst in packs:
        builder = PolicyBuilder(
            os.path.join(DSL_ROOT, src),
            os.path.join(COMPILED_ROOT, dst)
        )
        if not builder.build():
            print(f"Failed to build {src}")
            exit(1)
    
    # 2. Initialize Engine
    print("\n2. Initializing Compliance Engine...")
    config = {"thresholds": {"risk_score": 50}} # Mock config
    engine = ComplianceEngine(config)
    
    print(f"Loaded {len(engine.policies)} compiled rules.")
    if len(engine.policies) == 0:
        print("No policies loaded!")
        exit(1)

    # 3. Create Mock Signals & Monkey Patch
    # We need to simulate Phase 3 controls returning these signals
    phase3_mock_signals = {
        "secrets.detected": True,
        "secrets.severity": "HIGH",
        "approvals.count": 1,
        "approvals.security_review": 1,
        "privileged.is_sensitive": False,
        "licenses.banned_detected": False,
        "env.production_violation": False,
        "licenses.id": "MIT"
    }
    
    # Validation of Acme Policy (Risk Score needs to be in 'features' usually or raw)
    # The DSL uses 'deployment.risk_score'. 
    # CoreRiskControl emits 'violation_severity' -> mapped to ?
    # Let's inject it into phase3 mock for simplicity or ensure it matches
    phase3_mock_signals["deployment.risk_score"] = 85

    # Monkey Path the registry
    engine.control_registry.run_all = lambda ctx: {"signals": phase3_mock_signals, "findings": []}

    print("\n3. Running Evaluation...")
    # We must provide 'diff' to trigger Phase 3 execution path
    raw_inputs = {
        "diff": {"headers.h": "+test"}, 
        "total_churn": 100,
        "additions": 50,
        "deletions": 50,
        "files_changed": ["headers.h"],
        "per_file_churn": []
    }
    result = engine.evaluate(raw_inputs)
    
    print(f"Overall Status: {result.overall_status}")
    print(f"Total Policy Results: {len(result.results)}")
    
    # 4. Verification Assertions
    triggered_rules = [r for r in result.results if r.triggered]
    print(f"Triggered Rules: {len(triggered_rules)}")
    
    # Check Specific Rules presence
    rule_ids = [r.policy_id for r in triggered_rules]
    
    # SOC 2 CC6.1 (Secret detection)
    assert any("SOC2-CC6" in rid for rid in rule_ids), "Missing SOC2 Secret Rule"
    
    # Acme Risk Rule (Risk > 80)
    assert any("ACME-Sec-001" in rid for rid in rule_ids), "Missing Acme Risk Rule"
    
    # Check Metadata Injection
    # Find a SOC2 rule specifically to test traceability, as custom rules might not have standard compliance metadata
    soc2_rule = next((r for r in triggered_rules if "SOC2" in r.policy_id), None)
    if not soc2_rule:
        print("Error: No SOC2 rule triggered to verify traceability against.")
        exit(1)

    sample = soc2_rule
    print(f"\n4. Traceability Check ({sample.policy_id}):")
    print(sample.traceability)
    assert sample.traceability is not None
    assert "compliance" in sample.traceability
    
    # Check Overall Blocking
    if result.overall_status != "BLOCK":
        print("Expected BLOCK status due to secrets and high risk")
        exit(1)
    
    print("\nEnd-to-End Integration Verified Successfully!")

if __name__ == "__main__":
    verify_integration()

