"""Decision-id stability across CI re-runs — allowlist architecture (PR #128).

History
-------
The 2026-04-29 demo on PR #125 found that running the same PR twice
produced different `decision_id` values because run-of-record fields
were drifting into the seed used by `_deterministic_decision_id`.

  - PR #126 scrubbed `signals.workflow_run.run_id` + `run_attempt`.
    Empirical re-run found `issued_at` was still drifting.
  - PR #127 dropped `issued_at` from the seed.
    Empirical re-run found `signals.source_ref` and
    `signals.workflow_run.ref` + `signals.workflow_run.sha`
    were still drifting.
  - PR #128 (this commit) replaces the blocklist with an allowlist —
    only verdict-bearing signals (`metrics`, `dependency_provenance`,
    `override_flags`) flow into the seed.  Anything else, including
    future fields a contributor adds without thinking about
    determinism, is treated as run-of-record by default.

Forensic chain unchanged: full `signals` (with `workflow_run`,
`source_ref`, etc.) still flows into `bundle.signals` → DSSE
attestation, so "which CI run signed this?" queries work.

Contract tests live below in `TestSignalKeyClassificationContract`.
They are the durable safety net against the next leak.
"""
from __future__ import annotations

from typing import Any, Dict

import pytest

from releasegate.attestation.service import (
    _VERDICT_BEARING_SIGNAL_KEYS,
    _seed_signals,
    build_bundle_from_analysis_result,
)


# ── Test classification of every signal key that cli.py is known to emit ───
# This MUST stay in sync with `releasegate/cli.py` lines ~1132-1157
# (`signals_payload` construction).  When a contributor adds a new key,
# the contract test `test_realistic_signals_payload_keys_are_classified`
# fails until they classify it here.
#
# Verdict-bearing: keys that should affect `decision_id` because two
# runs that differ in this key represent two genuinely different
# governance verdicts.
_KNOWN_VERDICT_BEARING_SIGNAL_KEYS = frozenset({
    "metrics",
    "dependency_provenance",
    "override_flags",
})

# Run-of-record: keys that describe the CI invocation itself (run id,
# branch ref, who triggered it).  Two runs that differ only in these
# keys MUST produce the same `decision_id`.  These keys still appear
# in `bundle.signals` for forensic replay.
_KNOWN_RUN_OF_RECORD_SIGNAL_KEYS = frozenset({
    "source_ref",
    "workflow_run",
})


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


def _realistic_workflow_run(*, run_id: str, run_attempt: str = "1",
                            ref: str = "refs/pull/125/merge",
                            sha: str = "abc123def456") -> Dict[str, Any]:
    """Mirrors cli.py:1141-1155 verbatim — every field set from a
    GITHUB_* env var.  Use this in determinism tests so we exercise
    the *full* run-of-record envelope, not just a subset.
    """
    return {
        "provider": "github-actions",
        "repository": "org/service-api",
        "workflow": "Compliance Check",
        "run_id": run_id,
        "run_attempt": run_attempt,
        "actor": "alice",
        "job": "compliance",
        "ref": ref,
        "sha": sha,
    }


def _realistic_signals_payload(*, run_id: str = "9999",
                               source_ref: str = "refs/pull/125/merge",
                               workflow_ref: str = "refs/pull/125/merge",
                               workflow_sha: str = "abc123def456") -> Dict[str, Any]:
    """The full shape cli.py:1132-1157 builds in CI.

    Used by the contract test (every key must be classified) and by
    the empirical-regression test (every run-of-record field can vary
    between runs without changing decision_id).
    """
    return {
        "metrics": {
            "changed_files_count": 1,
            "additions": 1,
            "deletions": 0,
            "total_churn": 1,
        },
        "dependency_provenance": {
            "satisfied": True,
            "lockfile_required": False,
            "lockfiles_found": ["requirements.txt"],
            "hashes": [],
            "reason_codes": [],
            "combined_hash": "sha256:abc",
        },
        "source_ref": source_ref,
        "workflow_run": _realistic_workflow_run(
            run_id=run_id, ref=workflow_ref, sha=workflow_sha,
        ),
    }


# ─── Contract tests — the durable safety net ────────────────────────────────
class TestSignalKeyClassificationContract:
    """These tests are why PR #128 exists.  After two iterations of the
    blocklist-and-find-the-next-leak cycle, the architectural decision
    is: every signal key cli.py writes must be explicitly classified.
    Any unclassified key fails the test, before the demo can fail.
    """

    def test_seed_signals_allowlist_matches_test_classification(self) -> None:
        """Production allowlist (`_VERDICT_BEARING_SIGNAL_KEYS`) and
        the test's known-verdict-bearing set must be equal.  If they
        drift, either the prod code added a verdict-bearing field
        without updating tests, or the tests added one without
        updating prod.  Either is a bug.
        """
        assert _VERDICT_BEARING_SIGNAL_KEYS == _KNOWN_VERDICT_BEARING_SIGNAL_KEYS

    def test_classification_sets_are_disjoint(self) -> None:
        """A key cannot be both verdict-bearing and run-of-record."""
        overlap = _KNOWN_VERDICT_BEARING_SIGNAL_KEYS & _KNOWN_RUN_OF_RECORD_SIGNAL_KEYS
        assert overlap == frozenset(), f"keys appear in both sets: {sorted(overlap)}"

    def test_realistic_signals_payload_keys_are_classified(self) -> None:
        """Every key cli.py puts into signals_payload must be in
        either the verdict-bearing or the run-of-record set.

        When a contributor adds a new field to cli.py:1132-1157, this
        test fails with the unclassified key in the message, forcing
        an explicit decision: does this drive the verdict, or is it
        just metadata about the run?
        """
        keys = set(_realistic_signals_payload().keys())
        classified = _KNOWN_VERDICT_BEARING_SIGNAL_KEYS | _KNOWN_RUN_OF_RECORD_SIGNAL_KEYS
        unclassified = keys - classified
        assert unclassified == set(), (
            f"signals_payload keys are not classified: {sorted(unclassified)}.  "
            f"Add each to either _KNOWN_VERDICT_BEARING_SIGNAL_KEYS (and "
            f"`_VERDICT_BEARING_SIGNAL_KEYS` in attestation/service.py) or "
            f"_KNOWN_RUN_OF_RECORD_SIGNAL_KEYS."
        )

    def test_seed_signals_drops_every_run_of_record_key(self) -> None:
        """Sanity check the allowlist behaviour matches the
        classification: every run-of-record key must be absent from
        `_seed_signals` output, regardless of how rich its value is.
        """
        out = _seed_signals(_realistic_signals_payload())
        for key in _KNOWN_RUN_OF_RECORD_SIGNAL_KEYS:
            assert key not in out, (
                f"run-of-record key {key!r} leaked into seed: {sorted(out)}"
            )

    def test_seed_signals_keeps_every_verdict_bearing_key(self) -> None:
        """Mirror of the above: every verdict-bearing key present in
        the input is preserved in the seed output."""
        payload = _realistic_signals_payload()
        out = _seed_signals(payload)
        for key in _KNOWN_VERDICT_BEARING_SIGNAL_KEYS:
            if key in payload:
                assert key in out
                assert out[key] == payload[key]


# ── _seed_signals helper, allowlist semantics ───────────────────────────────
class TestSeedSignalsAllowlist:
    def test_drops_workflow_run_entirely(self) -> None:
        """Allowlist semantics: any field not explicitly in
        `_VERDICT_BEARING_SIGNAL_KEYS` is dropped, including
        `workflow_run` regardless of which subkeys it contains.
        """
        signals = {"metrics": {"churn": 5}, "workflow_run": _realistic_workflow_run(run_id="9999")}
        out = _seed_signals(signals)
        assert "workflow_run" not in out
        # Verdict-bearing field still present.
        assert out["metrics"] == signals["metrics"]

    def test_drops_source_ref(self) -> None:
        signals = {
            "metrics": {"churn": 5},
            "source_ref": "refs/pull/125/merge",
        }
        out = _seed_signals(signals)
        assert "source_ref" not in out
        assert out["metrics"] == signals["metrics"]

    def test_drops_unknown_future_fields_by_default(self) -> None:
        """The whole point of the allowlist: a brand-new field that
        hasn't been classified is excluded by default, instead of
        leaking into the seed and breaking determinism.
        """
        signals = {
            "metrics": {"churn": 5},
            "future_field_not_yet_classified": "anything",
        }
        out = _seed_signals(signals)
        assert "future_field_not_yet_classified" not in out

    def test_does_not_mutate_input(self) -> None:
        """The bundle keeps the unscrubbed signals — `_seed_signals`
        must not mutate the dict its caller still owns.
        """
        original = {"workflow_run": _realistic_workflow_run(run_id="9999")}
        snapshot = {"workflow_run": dict(original["workflow_run"])}
        _seed_signals(original)
        assert original == snapshot

    def test_handles_none_and_non_dict(self) -> None:
        assert _seed_signals(None) == {}
        assert _seed_signals("not-a-dict") == {}  # type: ignore[arg-type]
        assert _seed_signals({}) == {}

    def test_preserves_all_three_verdict_bearing_keys(self) -> None:
        signals = {
            "metrics": {"churn": 5, "files": 2},
            "dependency_provenance": {"npm": []},
            "override_flags": ["allow-once"],
            "workflow_run": _realistic_workflow_run(run_id="9999"),
            "source_ref": "refs/pull/125/merge",
        }
        out = _seed_signals(signals)
        assert out == {
            "metrics": signals["metrics"],
            "dependency_provenance": signals["dependency_provenance"],
            "override_flags": signals["override_flags"],
        }


# ── End-to-end: same PR, two CI runs → same decision_id ─────────────────────
class TestDecisionIdStableAcrossReruns:
    """The headline contract: same PR + same commit + same policy yields
    the same decision_id even when every run-of-record field differs.
    """

    def test_same_pr_different_run_id_yields_same_decision_id(self) -> None:
        signals_run1 = {
            "metrics": {"churn": 5},
            "workflow_run": _realistic_workflow_run(run_id="9991"),
        }
        signals_run2 = {
            "metrics": {"churn": 5},
            "workflow_run": _realistic_workflow_run(run_id="9999"),
        }
        bundle1 = _build(signals=signals_run1)
        bundle2 = _build(signals=signals_run2)
        assert bundle1.decision_id == bundle2.decision_id

    def test_same_pr_different_run_attempt_yields_same_decision_id(self) -> None:
        signals_run1 = {"workflow_run": _realistic_workflow_run(run_id="100", run_attempt="1")}
        signals_run2 = {"workflow_run": _realistic_workflow_run(run_id="100", run_attempt="3")}
        bundle1 = _build(signals=signals_run1)
        bundle2 = _build(signals=signals_run2)
        assert bundle1.decision_id == bundle2.decision_id

    def test_decision_id_stable_when_only_timestamp_differs(self) -> None:
        """Empirical regression case from PR #127."""
        bundle_open = _build(
            signals={"workflow_run": _realistic_workflow_run(run_id="100")},
            timestamp="2026-04-29T19:46:27Z",
        )
        bundle_after_merge = _build(
            signals={"workflow_run": _realistic_workflow_run(run_id="999")},
            timestamp="2026-04-29T22:36:45Z",
        )
        assert bundle_open.decision_id == bundle_after_merge.decision_id

    def test_local_dev_no_signals_matches_ci_with_only_run_metadata(self) -> None:
        """A local-dev run (no workflow_run, no source_ref) and a CI
        run whose signals contain ONLY run-of-record fields must
        produce identical decision_ids — both seed to "no signals at all".
        """
        bundle_local = _build(signals={})
        bundle_ci_no_verdict_signals = _build(signals={
            "source_ref": "refs/heads/main",
            "workflow_run": _realistic_workflow_run(run_id="9999"),
        })
        assert bundle_local.decision_id == bundle_ci_no_verdict_signals.decision_id

    def test_decision_id_stable_when_full_realistic_payload_drifts(self) -> None:
        """The empirical case from the 2026-04-29 PR #125 demo:
        between Run 1 (`pull_request:opened`) and Run 4 (`workflow_dispatch`
        post-merge), every run-of-record field changed simultaneously
        — `workflow_run.run_id`, `run_attempt`, `ref`, `sha`,
        `source_ref`, plus the bundle timestamp.  decision_id MUST
        be identical.
        """
        run_open_event = _build(
            signals=_realistic_signals_payload(
                run_id="25130213846",
                source_ref="refs/pull/125/merge",
                workflow_ref="refs/pull/125/merge",
                workflow_sha="merge-commit-sha",
            ),
            timestamp="2026-04-29T19:46:27Z",
        )
        run_dispatch_post_merge = _build(
            signals=_realistic_signals_payload(
                run_id="25137949107",
                source_ref="refs/heads/main",
                workflow_ref="refs/heads/main",
                workflow_sha="main-head-sha",
            ),
            timestamp="2026-04-29T22:36:45Z",
        )
        assert run_open_event.decision_id == run_dispatch_post_merge.decision_id


# ── Forensics still preserved (bundle keeps full signals) ───────────────────
class TestForensicMetadataPreserved:
    """The allowlist scrubs run-of-record from the *seed*, NOT from the
    bundle.  bundle.signals still goes into the DSSE attestation, so
    forensic queries ("which CI run signed this?") work.
    """

    def test_bundle_signals_retain_full_workflow_run(self) -> None:
        signals = {"workflow_run": _realistic_workflow_run(run_id="12345", run_attempt="2")}
        bundle = _build(signals=signals)
        assert bundle.signals["workflow_run"]["run_id"] == "12345"
        assert bundle.signals["workflow_run"]["run_attempt"] == "2"
        assert bundle.signals["workflow_run"]["actor"] == "alice"

    def test_bundle_signals_retain_source_ref(self) -> None:
        signals = {"source_ref": "refs/pull/125/merge"}
        bundle = _build(signals=signals)
        assert bundle.signals["source_ref"] == "refs/pull/125/merge"

    def test_bundle_signals_retain_full_realistic_payload(self) -> None:
        """Both verdict-bearing AND run-of-record signals survive
        intact in `bundle.signals` — only the seed is filtered.
        """
        payload = _realistic_signals_payload()
        bundle = _build(signals=payload)
        assert bundle.signals == payload

    def test_bundle_timestamp_records_issued_at_for_forensics(self) -> None:
        """Removing `issued_at` from the seed (PR #127) must NOT remove
        it from the bundle — DSSE needs the exact issuance moment.
        """
        bundle = _build(signals={}, timestamp="2026-04-29T19:46:27Z")
        assert bundle.timestamp.startswith("2026-04-29T19:46:27")


# ── Determinism the allowlist MUST NOT weaken ───────────────────────────────
class TestDeterminismOfStableInputs:
    """Verdict-bearing fields must continue to drive decision_id —
    we're carving out run-of-record envelopes, not weakening
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
        bundle1 = _build(signals={"workflow_run": _realistic_workflow_run(run_id="1")})
        bundle2 = build_bundle_from_analysis_result(
            tenant_id="tenant-test", repo="org/service-api", pr_number=125,
            commit_sha="abc123def456",
            policy_hash="policy-hash",
            policy_version="1.0.0",
            policy_bundle_hash="DIFFERENT-policy-bundle-hash",  # ← changed
            risk_score=0.10, decision="PASS",
            reason_codes=["RISK_LOW_HEURISTIC"],
            signals={"workflow_run": _realistic_workflow_run(run_id="1")},
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

    def test_different_metrics_still_drive_decision_id(self) -> None:
        """A change to verdict-bearing signals (metrics) MUST still
        produce a different decision_id.  This guards against an
        over-aggressive allowlist that would make the seed insensitive
        to genuine governance evidence.
        """
        bundle_a = _build(signals={"metrics": {"churn": 5}})
        bundle_b = _build(signals={"metrics": {"churn": 50}})
        assert bundle_a.decision_id != bundle_b.decision_id

    def test_different_dependency_provenance_still_drives_decision_id(self) -> None:
        bundle_a = _build(signals={"dependency_provenance": {"satisfied": True}})
        bundle_b = _build(signals={"dependency_provenance": {"satisfied": False}})
        assert bundle_a.decision_id != bundle_b.decision_id

    def test_different_override_flags_still_drive_decision_id(self) -> None:
        bundle_a = _build(signals={"override_flags": []})
        bundle_b = _build(signals={"override_flags": ["allow-once"]})
        assert bundle_a.decision_id != bundle_b.decision_id
