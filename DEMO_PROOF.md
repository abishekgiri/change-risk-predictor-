# ReleaseGate Public Demo Proof — PR #125

This document records the empirical end-to-end verification of ReleaseGate's deterministic-governance contract, performed on a real public pull request in this repository.

## What was tested

A live PR (`#125`) was opened, automatically gated by `compliance-check.yml`, and re-triggered through the `workflow_dispatch` path multiple times. The goal: confirm that **same PR + same commit + same policy + same engine version produces the same `decision_id`**, with idempotent storage on Render Postgres.

## Verified outcomes (post-v2.2.0)

Two consecutive runs of PR #125 against `main`, both invoked via `gh workflow run compliance-check.yml --ref main -f pr_number=125`, produced **identical** governance verdicts:

| | Run 5 | Run 6 |
|---|---|---|
| `decision_id` | `analysis-c7ad8c773924c7bc3975be8e` | `analysis-c7ad8c773924c7bc3975be8e` ✅ |
| `verdict` | `PASS` | `PASS` ✅ |
| `risk_level` | `LOW` | `LOW` ✅ |
| `reason_codes` | `["RISK_LOW_HEURISTIC"]` | `["RISK_LOW_HEURISTIC"]` ✅ |
| `errors` | `[]` | `[]` ✅ |
| GitHub workflow run | [25142951730](https://github.com/abishekgiri/change-risk-predictor-/actions/runs/25142951730) | [25143100468](https://github.com/abishekgiri/change-risk-predictor-/actions/runs/25143100468) |

**Storage idempotency on Render Postgres** (under `tenant_id='local'`):

| Table | Behaviour confirmed |
|---|---|
| `audit_decisions` | Multiple rows possible (one per signing event), all sharing the same `decision_id` — the verdict identity is stable across re-runs. |
| `audit_attestations` | One **immutable row per CI run** (post-#132). `attestation_id` = `signed_payload_hash`, per-run unique. Multiple rows accumulate for the same `decision_id` — one per signing event — and existing rows are never overwritten. Re-recording the same DSSE artifact verbatim is idempotent (PRIMARY KEY collision swallowed). |
| `cross_system_correlations` | Single row. `correlation_id` is `cor_<sha1(tenant\|repo\|pr\|sha)>`, stable across runs; the UPDATE-on-collision path tops up `rg_decision_ids`. |
| `change_records` | Single row. `change_id` is `chg_<sha1(tenant\|decision_id)>`, stable across runs; INSERT collides on the unique constraint and is swallowed. **Row count does not grow on retry.** |

## What stays per-run (the cryptographic audit chain)

While `decision_id` is deterministic by design, **every CI invocation still produces its own DSSE-signed cryptographic envelope** with run-of-record metadata for forensic replay:

| Per-run field | Where it lives | Run 5 example | Run 6 example |
|---|---|---|---|
| `attestation_id` | `compliance_report.json` + `audit_attestations` row PK | `dbcb638368850c…` | `abe4bed8477890e1…` |
| `signed_payload_hash` | `compliance_report.json` (= `attestation_id` by construction) | `sha256:dbcb638368850c…` | `sha256:abe4bed8477890e1…` |
| DSSE Ed25519 signature bytes | `releasegate.dsse.json` | `9N6Tvwf739bCeh76+SBA…` | `SgTdHUjt7G+RTWgp4xtr…` |
| `bundle.timestamp` | DSSE predicate | issuance moment of Run 5 | issuance moment of Run 6 |
| `bundle.signals.workflow_run.run_id` | DSSE predicate | `25142951730` | `25143100468` |
| `bundle.signals.workflow_run.run_attempt` | DSSE predicate | `1` | `1` |
| `bundle.signals.source_ref` | DSSE predicate | per-run env-var value | per-run env-var value |
| `bundle.signals.workflow_run.ref`, `.sha`, `.actor` | DSSE predicate | per-run env-var values | per-run env-var values |
| `evidence.signal_hash` | DSSE predicate | `sha256:33435e…` | `sha256:c954bd…` |
| `evidence.decision_bundle_hash` | DSSE predicate | `sha256:b413d2…` | `sha256:d0f8c2…` |
| `audit_attestations.created_at` | Render Postgres | timestamp of Run 5 signing | timestamp of Run 6 signing |
| `deploy_id` (in `cross_system_correlations`, `change_records`) | Render Postgres | `gha_25142951730_a1` | `gha_25143100468_a1` |

Each DSSE artifact is its own cryptographically signed record of *that specific CI run's signing event*, with the full GitHub-Actions run-of-record envelope intact for compliance replay. Per-run uniqueness is end-to-end: `attestation_id`, `signed_payload_hash`, the DSSE signature bytes, and the bundle's run-of-record fields all differ per CI invocation; `audit_attestations` accumulates one immutable row per signing event.

> **Historical note.** The Run 5 / Run 6 values for `attestation_id` shown above are what the post-#132 architecture will produce. Pre-#132 (the merged v2.2.0 era), `record_release_attestation()` short-circuited via a `(tenant_id, decision_id)` lookup and returned the first-stored `attestation_id` on subsequent runs, so re-runs incorrectly collapsed onto a single audit-log row even though the on-disk DSSE artifacts were genuinely per-run. PR #132 dropped the legacy `uq_audit_attestations_tenant_decision` index and removed the early-return path; the PRIMARY KEY `(tenant_id, attestation_id)` now provides per-run uniqueness on its own.

## What's NOT in the seed (and why)

`decision_id` is `analysis-<sha256(seed)[:24]>` where the seed is locked down to **verdict-bearing fields only** (PR #128):

```
seed = {
    tenant_id, repo, pr_number, commit_sha,
    policy_bundle_hash,
    decision, reason_codes, risk_score,
    signals (allowlisted to: metrics, dependency_provenance, override_flags),
}
```

Excluded by construction (run-of-record):

- `workflow_run.run_id`, `workflow_run.run_attempt`, `workflow_run.ref`, `workflow_run.sha`
- `workflow_run.actor`, `workflow_run.job`, `workflow_run.repository`, `workflow_run.workflow`, `workflow_run.provider`
- `source_ref`
- `issued_at` (= `pr.updated_at`)
- All other GitHub event metadata not explicitly classified as verdict-bearing

This is enforced by an **allowlist** (`_VERDICT_BEARING_SIGNAL_KEYS` in `releasegate/attestation/service.py`) plus a contract test (`tests/attestation/test_decision_id_stability.py::TestSignalKeyClassificationContract`) that fails CI if a contributor adds a new `signals_payload` key in `cli.py` without explicit classification. The next env-var-derived field is impossible to leak by construction.

## Reproduce yourself

The Render Postgres connection string (`RELEASEGATE_POSTGRES_DSN`) is not required to reproduce the determinism check — only to inspect the persisted rows.

```bash
# Trigger another run on the same PR.
gh workflow run compliance-check.yml --ref main -f pr_number=125

# Wait for completion and pull the artifact.
RUN=$(gh run list --workflow compliance-check.yml --event workflow_dispatch \
       --limit 1 --json databaseId -q '.[0].databaseId')
gh run watch "$RUN" --exit-status
gh run download "$RUN" -n releasegate-artifacts -D /tmp/releasegate-proof
jq '.decision_id' /tmp/releasegate-proof/compliance_report.json
# Expected (post-v2.2.0): "analysis-c7ad8c773924c7bc3975be8e"
```

To confirm the per-run cryptographic envelope is genuinely per-run, compare DSSE artifacts across two invocations:

```bash
jq '.signatures[0].sig' /tmp/releasegate-proof-r1/releasegate.dsse.json
jq '.signatures[0].sig' /tmp/releasegate-proof-r2/releasegate.dsse.json
# Different signature bytes → different signing event → per-run forensic envelope.
```

For storage idempotency, query Render with the standard 3-table sanity-join:

```sql
SELECT cr.change_id, ad.decision_id, cr.created_at
FROM change_records cr
JOIN cross_system_correlations csc
  ON csc.correlation_id = cr.correlation_id AND csc.tenant_id = cr.tenant_id
JOIN audit_decisions ad
  ON ad.decision_id = csc.decision_id AND ad.tenant_id = csc.tenant_id
WHERE cr.tenant_id = 'local' AND ad.pr_number = 125
ORDER BY cr.created_at DESC;
-- change_records.change_id collides on the unique constraint across reruns;
-- audit_decisions accumulates one row per signing event, all with the same
-- decision_id.
```

For per-run audit envelope visibility, query `audit_attestations` directly:

```sql
SELECT attestation_id, signed_payload_hash, created_at
FROM audit_attestations
WHERE tenant_id = 'local' AND decision_id = 'analysis-c7ad8c773924c7bc3975be8e'
ORDER BY created_at ASC;
-- One row per CI invocation (post-#132).
-- attestation_id and signed_payload_hash are equal by construction and
-- per-run unique. decision_id stays the same across all rows.
```

## Architecture references

- **Release**: [v2.2.0 — Deterministic Governance](https://github.com/abishekgiri/change-risk-predictor-/releases/tag/v2.2.0)
- **CHANGELOG**: see `[v2.2.0]` entry in [CHANGELOG.md](CHANGELOG.md)
- **Allowlist + contract test**: `releasegate/attestation/service.py` (`_VERDICT_BEARING_SIGNAL_KEYS`, `_seed_signals`) and `tests/attestation/test_decision_id_stability.py`
- **PR for the allowlist architecture**: [#128](https://github.com/abishekgiri/change-risk-predictor-/pull/128)
- **Earlier blocklist iterations** (superseded by #128): [#126](https://github.com/abishekgiri/change-risk-predictor-/pull/126), [#127](https://github.com/abishekgiri/change-risk-predictor-/pull/127)
- **Per-run unique `attestation_id`** — drops the legacy `(tenant_id, decision_id)` UNIQUE index and the SELECT-and-return short-circuit so each CI run lands its own immutable `audit_attestations` row: [#132](https://github.com/abishekgiri/change-risk-predictor-/pull/132) and `tests/audit/test_attestation_per_run_uniqueness.py`
- **DSN validation safety net**: [#122](https://github.com/abishekgiri/change-risk-predictor-/pull/122)
- **Cold-start canonical schema fix**: [#123](https://github.com/abishekgiri/change-risk-predictor-/pull/123)
- **Workflow fail-loud-on-missing-report**: [#124](https://github.com/abishekgiri/change-risk-predictor-/pull/124)
- **Verification runs cited above**: [Run 5](https://github.com/abishekgiri/change-risk-predictor-/actions/runs/25142951730), [Run 6](https://github.com/abishekgiri/change-risk-predictor-/actions/runs/25143100468)

## Tagline

> **Deterministic governance with per-run cryptographic audit trails.**

The verdict is reproducible — same inputs, same `decision_id`, same `change_id`, idempotent storage. Every execution still produces its own DSSE-signed envelope with full run-of-record metadata, so auditors get both: a stable judgement plus a per-run forensic chain.
