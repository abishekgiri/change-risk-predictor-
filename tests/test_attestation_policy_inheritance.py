from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_analysis_result


def test_attestation_includes_policy_scope_and_resolution_hash():
    bundle = build_bundle_from_analysis_result(
        tenant_id="tenant-test",
        repo="org/service-api",
        pr_number=42,
        commit_sha="1234567890abcdef",
        policy_hash="legacy-policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="legacy-policy-bundle",
        risk_score=0.8,
        decision="BLOCK",
        reason_codes=["POLICY_BLOCKED"],
        signals={"changed_files": 10},
        engine_version="2.0.0",
        timestamp="2026-02-13T00:00:00Z",
        policy_scope=["org", "repo", "environment"],
        policy_resolution_hash="abc123resolutionhash",
    )

    attestation = build_attestation_from_bundle(bundle)
    policy = attestation["policy"]
    assert policy["policy_scope"] == ["org", "repo", "environment"]
    assert policy["policy_resolution_hash"] == "abc123resolutionhash"
