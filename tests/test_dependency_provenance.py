from releasegate.attestation.service import build_attestation_from_bundle, build_bundle_from_analysis_result
from releasegate.signals.dependency_provenance import (
    build_dependency_provenance_signal,
    combined_lockfile_hash,
    discover_lockfiles,
    hash_lockfiles,
)


class MockContentProvider:
    def __init__(self, files):
        self.files = dict(files)

    def get_file_content(self, _repo, path, ref=None):
        _ = ref
        return self.files.get(path)


def test_discover_lockfiles_detects_expected_files():
    provider = MockContentProvider(
        {
            "requirements.txt": "flask==3.0.0",
            "go.sum": "github.com/x/y v1.0.0 h1:abc",
            "README.md": "ignore",
        }
    )
    found = discover_lockfiles(provider, "org/repo", "headsha")
    assert found == ["go.sum", "requirements.txt"]


def test_hashing_is_deterministic_and_order_independent():
    provider = MockContentProvider(
        {
            "poetry.lock": "A",
            "requirements.txt": "B",
        }
    )
    lockfiles = ["requirements.txt", "poetry.lock"]
    first = hash_lockfiles(provider, "org/repo", "sha", lockfiles)
    second = hash_lockfiles(provider, "org/repo", "sha", list(reversed(lockfiles)))

    assert first == second
    assert combined_lockfile_hash(first) == combined_lockfile_hash(second)


def test_policy_required_missing_lockfiles_fails():
    provider = MockContentProvider({})
    signal = build_dependency_provenance_signal(
        provider=provider,
        repo="org/repo",
        ref="headsha",
        lockfile_required=True,
    )
    assert signal["satisfied"] is False
    assert signal["reason_codes"] == ["LOCKFILE_REQUIRED_MISSING"]
    assert signal["lockfiles_found"] == []


def test_policy_required_with_lockfile_passes():
    provider = MockContentProvider({"package-lock.json": "{}"})
    signal = build_dependency_provenance_signal(
        provider=provider,
        repo="org/repo",
        ref="headsha",
        lockfile_required=True,
    )
    assert signal["satisfied"] is True
    assert signal["reason_codes"] == []
    assert signal["lockfiles_found"] == ["package-lock.json"]


def test_policy_optional_with_no_lockfiles_passes():
    provider = MockContentProvider({})
    signal = build_dependency_provenance_signal(
        provider=provider,
        repo="org/repo",
        ref="headsha",
        lockfile_required=False,
    )
    assert signal["satisfied"] is True
    assert signal["reason_codes"] == []


def test_attestation_includes_dependency_provenance_signal():
    dependency_provenance = {
        "lockfiles_found": ["requirements.txt"],
        "hashes": [{"path": "requirements.txt", "sha256": "sha256:abc", "size_bytes": 12}],
        "combined_hash": "sha256:def",
        "lockfile_required": True,
        "satisfied": True,
        "reason_codes": [],
    }
    bundle = build_bundle_from_analysis_result(
        tenant_id="tenant-test",
        repo="org/service-api",
        pr_number=99,
        commit_sha="abcdef1234567890",
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.1,
        decision="ALLOW",
        reason_codes=["RISK_LOW_HEURISTIC"],
        signals={"dependency_provenance": dependency_provenance},
        engine_version="2.0.0",
        timestamp="2026-02-13T00:00:00Z",
    )
    attestation = build_attestation_from_bundle(bundle)
    assert attestation["evidence"]["dependency_provenance"] == dependency_provenance
