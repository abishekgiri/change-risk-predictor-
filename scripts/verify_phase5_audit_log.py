import os
import json
import uuid
import shutil
from datetime import datetime, timezone
from compliancebot.audit.log import AuditLogger
from compliancebot.audit.types import AuditEvent

REPO = "abishekgiri/change-risk-predictor"
LOG_DIR = "audit_bundles/logs/abishekgiri_change-risk-predictor"
LOG_FILE = f"{LOG_DIR}/audit.ndjson"

def verify_audit_log():
    print("Verifying Phase 5 Audit Logging")
    print("===============================")
    
    # 1. Cleanup
    if os.path.exists(LOG_DIR):
        shutil.rmtree(LOG_DIR)
    
    logger = AuditLogger(REPO)
    
    # 2. Create Events
    print("\n1. Generating Chain of 3 Events...")
    events = []
    for i in range(3):
        evt = AuditEvent(
            audit_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor="test-user",
            repo=REPO,
            pr_number=100 + i,
            head_sha=f"sha{i}",
            overall_status="PASS",
            risk_score=10 * i,
            bundle_manifest_hash="dummy_hash",
            previous_event_hash=None 
        )
        h = logger.append_event(evt)
        events.append((evt, h))
        print(f" Event {i}: {h}")
    
    # 3. Verify File Exists
    if not os.path.exists(LOG_FILE):
        print("❌ Log file not created")
        exit(1)
    print("✅ Log file created")
    
    # 4. Verify Content & Chain
    print("\n2. Verifying Hash Chain...")
    with open(LOG_FILE) as f:
        lines = [json.loads(line) for line in f]
    
    assert len(lines) == 3
    
    # Check Genesis
    assert lines[0]['previous_event_hash'] == "0000000000000000000000000000000000000000000000000000000000000000"
    assert lines[0]['event_hash'] == events[0][1]
    
    # Check Chain
    assert lines[1]['previous_event_hash'] == lines[0]['event_hash']
    assert lines[2]['previous_event_hash'] == lines[1]['event_hash']
    
    print("✅ Hash chain matches")
    
    # 5. Verify Integrity Check Logic (simulated)
    print("\n3. Testing Tamper Detection...")
    
    # Tamper with event 1
    lines[1]['risk_score'] = 999 
    # Recalculate hash (which would be different)
    
    # In a real verify tool, we would recompute hashes line by line.
    # temp_logger = AuditLogger("temp") -> Use existing logger instance logic
    
    recomputed_hash = logger._compute_hash(lines[1])
    original_stored_hash = lines[1]['event_hash']
    
    if recomputed_hash != original_stored_hash:
        print(f"✅ Tampering Detected! Stored: {original_stored_hash}, Computed: {recomputed_hash}")
    else:
        print("❌ Tampering NOT detected")
        exit(1)

    print("\nAudit Log Verification Successful")

if __name__ == "__main__":
    verify_audit_log()

