from __future__ import annotations

import json
from pathlib import Path

from releasegate.reporting import (
    build_compliance_report,
    exit_code_for_verdict,
    write_json_report_atomic,
)


def test_exit_code_monitor_never_blocks():
    assert exit_code_for_verdict("monitor", "FAIL") == 0
    assert exit_code_for_verdict("monitor", "PASS") == 0


def test_exit_code_enforce_blocks_on_fail():
    assert exit_code_for_verdict("enforce", "FAIL") == 1
    assert exit_code_for_verdict("enforce", "WARN") == 0
    assert exit_code_for_verdict("enforce", "PASS") == 0


def test_report_written_even_on_fail(tmp_path: Path):
    report = build_compliance_report(
        repo="example/repo",
        pr_number=1,
        head_sha="0" * 40,
        base_sha="1" * 40,
        tenant_id="default",
        control_result="BLOCK",
        risk_score=99.0,
        risk_level="HIGH",
        reasons=["LOCKFILE_REQUIRED_MISSING"],
        reason_codes=["LOCKFILE_REQUIRED_MISSING"],
        metrics={
            "changed_files_count": 1,
            "additions": 2,
            "deletions": 3,
            "total_churn": 5,
        },
        dependency_provenance={},
        attached_issue_keys=[],
        policy_hash="deadbeef",
        policy_resolution_hash="deadbeef",
        policy_scope=["org"],
        enforcement_mode="monitor",
        decision_id="analysis-test",
        attestation_id=None,
        signed_payload_hash=None,
        dsse_path=None,
        dsse_sigstore_bundle_path=None,
        artifacts_sha256_path=None,
        errors=["ATTESTATION_GENERATION_FAILED: missing signing key"],
    )

    out = tmp_path / "compliance_report.json"
    write_json_report_atomic(str(out), report)
    assert out.exists()

    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == "compliance_report_v1"
    assert loaded["verdict"] == "FAIL"
    assert loaded["control_result"] == "BLOCK"
    assert loaded["errors"]

