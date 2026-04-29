"""Decision-id stability across CI re-runs.

Background — the empirical demo on PR #125 (2026-04-29) found that
running the same PR twice produced different `decision_id` values.
The cause: `signals.workflow_run.run_id` (and `run_attempt`) were
included in the seed used by `_deterministic_decision_id`, and those
fields are unique per workflow invocation by definition.

That broke idempotent storage:
  - `correlation_id = sha1(tenant|repo|pr|sha)[:16]` was deterministic,
    so retries collapsed cleanly into the existing
    cross_system_correlations row.
  - `change_id     = sha1(tenant|decision_id)[:16]` was NOT deterministic
    (because decision_id varied), so each re-run inserted a new
    change_records row.

The fix in `_seed_signals` scrubs run-of-record fields from the seed
*only* — they remain in `bundle.signals`, the DSSE attestation, and
forensic queries, so "which CI run signed this?" is still answerable.

These tests pin down the contract so the next time someone adds a
field that varies per run, it gets caught here instead of empirically
during a demo.
"""
from __future__ import annotations

from typing import Any, Dict

import pytest

from releasegate.attestation.service import (
    _seed_signals,
    build_bundle_from_analysis_result,
)


# ── Helpers ─────────────────────────────────────────────────────────────────
def _build(*, signals: Dict[str, Any], timestamp: str = "2026-04-29T00:00:00Z"):
    """Mirror the analyze-pr call site shape."""
    return build_bundle_from_analysis_result(
        tenant_id="tenant-test",
        repo="org/service-api",
        pr_number=125,
        commit_sha="abc123def456",
        policy_hash="policy-hash",
        policy_version="1.0.0",
        policy_bundle_hash="policy-bundle-hash",
        risk_score=0.10,
        decision="PASS",
        reason_codes=["RISK_LOW_HEURISTIC"],
        signals=signals,
        engine_version="2.0.0",
        timestamp=timestamp,
    )


def _workflow_run(run_id: str, run_attempt: str = "1") -> Dict[str, Any]:
    """Realistic workflow_run shape from cli.py:1141-1155."""
    return {
        "provider": "github-actions",
        "repository": "org/service-api",
        "workflow": "Compliance Check",
        "run_id": run_id,
        "run_attempt": run_attempt,
        "actor": "alice",
        "job": "compliance",
        "ref": "refs/pull/125/merge",
        "sha": "abc123def456",
    }


# ── _seed_signals helper ────────────────────────────────────────────────────
class TestSeedSignals:
    def test_strips_run_id_and_run_attempt(self) -> None:
        signals = {"metrics": {"churn": 5}, "workflow_run": _workflow_run("9999")}
        out = _seed_signals(signals)
        assert "run_id" not in out["workflow_run"]
        assert "run_attempt" not in out["workflow_run"]
        # Stable fields preserved.
        assert out["workflow_run"]["repository"] == "org/service-api"
        assert out["workflow_run"]["actor"] == "alice"

    def test_drops_workflow_run_when_only_volatile_fields_present(self) -> None:
        """If `workflow_run` would become empty after scrubbing, drop the
        whole key — leaving an empty dict would still hash differently
        from a local-dev run that has no `workflow_run` at all.
        """
        signals = {"workflow_run": {"run_id": "x", "run_attempt": "1"}}
        out = _seed_signals(signals)
        assert "workflow_run" not in out

    def test_does_not_mutate_input(self) -> None:
        """The bundle keeps the unscrubbed signals — _seed_signals must
        not mutate the dict its caller still owns.
        """
        original = {"workflow_run": _workflow_run("9999")}
        snapshot = {"workflow_run": dict(original["workflow_run"])}
        _seed_signals(original)
        assert original == snapshot

    def test_handles_none_and_non_dict(self) -> None:
        assert _seed_signals(None) == {}
        assert _seed_signals("not-a-dict") == {}  # type: ignore[arg-type]
        assert _seed_signals({}) == {}

    def test_preserves_unrelated_signals(self) -> None:
        signals = {
            "metrics": {"churn": 5, "files": 2},
            "dependency_provenance": {"npm": []},
            "workflow_run": _workflow_run("9999"),
        }
        out = _seed_signals(signals)
        assert out["metrics"] == signals["metrics"]
        assert out["dependency_provenance"] == signals["dependency_provenance"]


# ── End-to-end: same PR, two CI runs → same decision_id ─────────────────────
class TestDecisionIdStableAcrossReruns:
    """The headline contract: same PR + same commit + same policy yields
    the same decision_id even when GITHUB_RUN_ID / GITHUB_RUN_ATTEMPT
    differ between invocations.
    """

    def test_same_pr_different_run_id_yields_same_decision_id(self) -> None:
        signals_run1 = {"metrics": {"churn": 5}, "workflow_run": _workflow_run("9991")}
        signals_run2 = {"metrics": {"churn": 5}, "workflow_run": _workflow_run("9999")}
        bundle1 = _build(signals=signals_run1)
        bundle2 = _build(signals=signals_run2)
        assert bundle1.decision_id == bundle2.decision_id

    def test_same_pr_different_run_attempt_yields_same_decision_id(self) -> None:
        signals_run1 = {"workflow_run": _workflow_run("100", run_attempt="1")}
        signals_run2 = {"workflow_run": _workflow_run("100", run_attempt="3")}
        bundle1 = _build(signals=signals_run1)
        bundle2 = _build(signals=signals_run2)
        assert bundle1.decision_id == bundle2.decision_id

    def test_local_dev_no_workflow_run_matches_ci_with_only_volatile_fields(self) -> None:
        """A local-dev run (no workflow_run) and a CI run whose
        workflow_run has only run_id/run_attempt should produce
        identical decision_ids — both seeds become "no workflow_run".
        """
        bundle_local = _build(signals={})
        bundle_ci_minimal = _build(
            signals={"workflow_run": {"run_id": "1", "run_attempt": "1"}}
        )
        assert bundle_local.decision_id == bundle_ci_minimal.decision_id


# ── Forensics still preserved ───────────────────────────────────────────────
class TestForensicMetadataPreserved:
    """Removing run_id from the seed must NOT remove it from the bundle.
    The DSSE attestation still needs to record exactly which CI run
    issued the decision so we can replay it for compliance.
    """

    def test_bundle_signals_retain_full_workflow_run(self) -> None:
        signals = {"workflow_run": _workflow_run("12345", run_attempt="2")}
        bundle = _build(signals=signals)
        assert bundle.signals["workflow_run"]["run_id"] == "12345"
        assert bundle.signals["workflow_run"]["run_attempt"] == "2"
        assert bundle.signals["workflow_run"]["actor"] == "alice"


# ── Determinism the fix MUST NOT weaken ─────────────────────────────────────
class TestDeterminismOfStableInputs:
    """Verdict-bearing fields must continue to drive decision_id —
    we're only carving out the run-of-record fields, not weakening
    sensitivity to actual governance inputs.
    """

    def test_different_commit_sha_yields_different_decision_id(self) -> None:
        bundle1 = build_bundle_from_analysis_result(
            tenant_id="tenant-test", repo="r", pr_number=1,
            commit_sha="aaa", policy_hash="ph", policy_version="1.0.0",
            policy_bundle_hash="pbh", risk_score=0.1, decision="PASS",
            reason_codes=[], signals={}, engine_version="2.0.0",
            timestamp="2026-04-29T00:00:00Z",
        )
        bundle2 = build_bundle_from_analysis_result(
            tenant_id="tenant-test", repo="r", pr_number=1,
            commit_sha="bbb", policy_hash="ph", policy_version="1.0.0",
            policy_bundle_hash="pbh", risk_score=0.1, decision="PASS",
            reason_codes=[], signals={}, engine_version="2.0.0",
            timestamp="2026-04-29T00:00:00Z",
        )
        assert bundle1.decision_id != bundle2.decision_id

    def test_different_policy_bundle_hash_yields_different_decision_id(self) -> None:
        bundle1 = _build(signals={"workflow_run": _workflow_run("1")})
        bundle2 = build_bundle_from_analysis_result(
            tenant_id="tenant-test", repo="org/service-api", pr_number=125,
            commit_sha="abc123def456",
            policy_hash="policy-hash",
            policy_version="1.0.0",
            policy_bundle_hash="DIFFERENT-policy-bundle-hash",  # ← changed
            risk_score=0.10, decision="PASS",
            reason_codes=["RISK_LOW_HEURISTIC"],
            signals={"workflow_run": _workflow_run("1")},
            engine_version="2.0.0",
            timestamp="2026-04-29T00:00:00Z",
        )
        assert bundle1.decision_id != bundle2.decision_id

    def test_different_decision_yields_different_decision_id(self) -> None:
        bundle_pass = _build(signals={})
        bundle_block = build_bundle_from_analysis_result(
            tenant_id="tenant-test", repo="org/service-api", pr_number=125,
            commit_sha="abc123def456",
            policy_hash="policy-hash",
            policy_version="1.0.0",
            policy_bundle_hash="policy-bundle-hash",
            risk_score=0.10, decision="BLOCK",  # ← changed
            reason_codes=["RISK_LOW_HEURISTIC"],
            signals={},
            engine_version="2.0.0",
            timestamp="2026-04-29T00:00:00Z",
        )
        assert bundle_pass.decision_id != bundle_block.decision_id

    def test_non_volatile_signals_changes_still_drive_decision_id(self) -> None:
        """Adding a non-workflow_run signal (e.g. metrics changing because
        the diff changed) MUST still produce a different decision_id.
        We're not making the seed insensitive to evidence — just to the
        run-of-record envelope.
        """
        bundle_a = _build(signals={"metrics": {"churn": 5}})
        bundle_b = _build(signals={"metrics": {"churn": 50}})
        assert bundle_a.decision_id != bundle_b.decision_id
