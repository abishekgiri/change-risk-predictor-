import os

from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_analysis_result
from releasegate.audit.attestations import record_release_attestation
from releasegate.cli import build_parser, main
from releasegate.config import DB_PATH
from releasegate.storage.schema import init_db


def test_cli_parser_includes_export_root():
    parser = build_parser()
    args = parser.parse_args(["export-root", "--date", "2026-02-13", "--out", "roots/2026-02-13.json"])
    assert args.cmd == "export-root"
    assert args.date == "2026-02-13"
    assert args.out == "roots/2026-02-13.json"


def test_cli_parser_includes_verify_inclusion():
    parser = build_parser()
    args = parser.parse_args(
        ["verify-inclusion", "--proof-file", "proof.json", "--format", "json"]
    )
    assert args.cmd == "verify-inclusion"
    assert args.proof_file == "proof.json"
    assert args.format == "json"


def test_cli_verify_inclusion_command_returns_zero(monkeypatch):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()

    bundle = build_bundle_from_analysis_result(
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=5,
        commit_sha="a" * 40,
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="bundle-hash",
        risk_score=0.8,
        decision="BLOCK",
        reason_codes=["POLICY_BLOCKED"],
        signals={"dependency_provenance": {}},
        engine_version="2.0.0",
        timestamp="2026-02-13T12:00:00Z",
    )
    attestation = build_attestation_from_bundle(bundle)
    attestation_id = record_release_attestation(
        decision_id=bundle.decision_id,
        tenant_id="tenant-a",
        repo="org/repo",
        pr_number=5,
        attestation=attestation,
    )

    prev_tenant = os.environ.get("RELEASEGATE_TENANT_ID")
    try:
        monkeypatch.setattr(
            "sys.argv",
            [
                "releasegate",
                "verify-inclusion",
                "--attestation-id",
                attestation_id,
                "--tenant",
                "tenant-a",
                "--format",
                "json",
            ],
        )
        assert main() == 0
    finally:
        if prev_tenant is None:
            os.environ.pop("RELEASEGATE_TENANT_ID", None)
        else:
            os.environ["RELEASEGATE_TENANT_ID"] = prev_tenant
