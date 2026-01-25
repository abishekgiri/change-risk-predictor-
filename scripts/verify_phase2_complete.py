#!/usr/bin/env python3
import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from compliancebot.engine import ComplianceEngine
from compliancebot.audit.evidence import EvidenceBundler

def main():
    print(" Starting Phase 2 End-to-End Verification...")
    
    # 1. Mock Configuration (Critical Path = auth/)
    config = {
        "critical_paths": {
            "high": ["auth/"]
        },
        "high_threshold": 50
    }
    
    # 2. Mock Signals (High Risk Scenario)
    # 2000 lines of churn in auth/login.py -> Should trigger High Churn & Critical Path policies
    raw_signals = {
        "repo_slug": "test/compliance-demo",
        "entity_type": "pr",
        "entity_id": "1001",
        "timestamp": "2026-01-22T12:00:00Z",
        "files_changed": ["auth/login.py"],
        "lines_added": 2000,
        "lines_deleted": 0,
        "total_churn": 2000,
        "per_file_churn": {"auth/login.py": 2000},
        "touched_services": ["auth"],
        "labels": [],
        "author": "junior_dev"
    }
    
    # 3. Initialize Engine
    print("✅ Initializing ComplianceEngine...")
    engine = ComplianceEngine(config)
    
    # 4. Evaluate
    print(" Evaluating Signals...")
    result = engine.evaluate(raw_signals)
    
    # 5. Check Control Result
    print(f" Control Result: {result.overall_status}")
    print(f" Violations: {[p.name for p in result.results if p.triggered]}")
    
    if result.overall_status != "BLOCK":
        print("❌ FAILED: Expected BLOCK status for high risk change.")
        sys.exit(1)
    
    # 6. Generate Audit Evidence
    print(" Generating Audit Bundle...")
    bundler = EvidenceBundler()
    
    # Need to construct ControlResult-like object for bundler?
    # EvidenceBundler.bundle(control_result, raw_signals, engine_metadata)
    # We first map ComplianceRunResult to ControlResult dict (like in server.py)
    control_result = {
        "control_result": result.overall_status,
        "severity": result.metadata.get("core_risk_level"),
        "violations": [p.name for p in result.results if p.triggered],
        "policies": [p.dict() for p in result.results],
        "evidence": {} # Mock evidence map
    }
    
    bundle = bundler.bundle(control_result, raw_signals, result.metadata)
    
    # 7. Print Bundle
    print("\n Evidence Bundle Preview:")
    print(json.dumps(bundle, indent=2))
    
    if bundle["control_result"] != "BLOCK":
        print("❌ FAILED: Evidence bundle has wrong status.")
        sys.exit(1)
    
    print("\n✅ Verification Successful: Phase 2 Complete.")

if __name__ == "__main__":
    main()

